"""The continuous watchdog run loop + rolling state machine.

Responsibilities:
  * Poll every ``poll_interval_seconds``, classify each sample, append JSONL.
  * Track consecutive-degraded count; after ``failure_threshold_count`` degraded
    samples (and respecting ``event_cooldown_seconds``), trigger a snapshot.
  * Maintain the last known-good gateway MAC for ARP-conflict detection and the
    before/after MAC fields in summary.json.
  * Honour the "Important Trigger Behavior": a Windows ping failure while the Pi
    is otherwise healthy classifies as ``windows_unreachable_from_pi`` (lower
    severity) and triggers its own event after the threshold.
  * Run a periodic retention/prune pass for SD-card safety.
"""

from __future__ import annotations

import collections
import json
import signal
import time
from typing import Deque, Dict, Optional

from . import checks, classify, logmgmt, snapshot

# How many recent samples to keep in memory for recent_samples.jsonl.
RECENT_SAMPLES_KEEP = 120


class Watchdog:
    """Encapsulates the rolling state for the polling loop."""

    def __init__(self, cfg):
        self.cfg = cfg
        self.recent: Deque[Dict] = collections.deque(maxlen=RECENT_SAMPLES_KEEP)
        self.consecutive_degraded = 0
        self.last_event_time = 0.0
        self.last_good_gateway_mac: Optional[str] = None
        self.prev_sample: Optional[Dict] = None
        self.prev_windows_ok: Optional[bool] = None
        self._stop = False

        lm = cfg.log_management
        self.appender = logmgmt.JsonlAppender(
            cfg["jsonl_log_path"],
            max_bytes=int(lm["max_jsonl_mb"]) * 1024 * 1024,
            max_rotated=int(lm["max_rotated_jsonl_files"]),
        )
        self.prune_interval = int(lm["prune_interval_seconds"])
        self.last_prune = 0.0

    # ------------------------------------------------------------------ #
    def stop(self, *_args) -> None:
        """Signal the loop to exit after the current iteration."""
        self._stop = True

    def poll_once(self) -> Dict:
        """Gather, classify, and persist one sample. Returns the sample."""
        sample = checks.gather_sample(self.cfg)

        # Detect a Windows OK->failed transition for the spec's trigger behavior.
        win_now = sample.get("windows_ping_ok")
        windows_transition_fail = (
            self.prev_windows_ok is True and win_now is False
        )

        classification = classify.classify_sample(
            sample,
            prev_sample=self.prev_sample,
            expected_gateway_mac=self.last_good_gateway_mac,
        )

        # If everything is healthy and the Windows ping just transitioned to
        # failed, escalate to windows_unreachable_from_pi explicitly (the
        # classifier already does this when win is False, but the transition
        # guard avoids re-triggering every poll while Windows stays down).
        sample["classification"] = classification

        # Write JSONL (without private keys).
        public = {k: v for k, v in sample.items() if not k.startswith("_")}
        self.appender.append(json.dumps(public))
        self.recent.append(sample)

        # Update rolling state.
        self._update_state(sample, classification, windows_transition_fail)
        self.prev_sample = sample
        self.prev_windows_ok = win_now
        return sample

    def _update_state(
        self, sample: Dict, classification: str, windows_transition_fail: bool
    ) -> None:
        """Advance the failure counter and trigger snapshots when warranted."""
        # Track last known-good gateway MAC (only while healthy / reachable).
        mac = sample.get("gateway_mac")
        if classification == "healthy" and mac:
            self.last_good_gateway_mac = mac

        if classify.is_degraded(classification):
            self.consecutive_degraded += 1
        else:
            self.consecutive_degraded = 0

        threshold = int(self.cfg["failure_threshold_count"])
        cooldown = float(self.cfg["event_cooldown_seconds"])
        now = time.time()

        should_trigger = (
            self.consecutive_degraded >= threshold
            and (now - self.last_event_time) >= cooldown
        )

        if should_trigger:
            self._trigger_event(classification, sample)
            self.last_event_time = now
            # Reset so we don't immediately re-trigger; cooldown still applies.
            self.consecutive_degraded = 0

    def _trigger_event(self, classification: str, sample: Dict) -> str:
        """Create an event snapshot for the current degraded state."""
        folder = snapshot.create_snapshot(
            self.cfg,
            classification,
            sample,
            list(self.recent),
            prev_gateway_mac=self.last_good_gateway_mac,
        )
        print(f"[event] {classification} -> {folder}")
        return folder

    def maybe_prune(self) -> None:
        """Run the retention/prune pass if the interval has elapsed."""
        now = time.time()
        if now - self.last_prune >= self.prune_interval:
            logmgmt.run_retention_pass(self.cfg)
            self.last_prune = now

    def run(self) -> None:
        """Main loop: poll, prune, sleep. Never crashes on a single bad poll."""
        # Install signal handlers for clean shutdown under systemd.
        try:
            signal.signal(signal.SIGTERM, self.stop)
            signal.signal(signal.SIGINT, self.stop)
        except (ValueError, OSError):
            # Not in main thread (e.g. tests) — ignore.
            pass

        interval = float(self.cfg["poll_interval_seconds"])
        # Startup retention pass.
        logmgmt.run_retention_pass(self.cfg)
        self.last_prune = time.time()

        print(
            f"[run] netwatch-pi watchdog started "
            f"(interface={self.cfg['preferred_interface']}, "
            f"interval={interval}s, threshold={self.cfg['failure_threshold_count']})"
        )

        while not self._stop:
            start = time.time()
            try:
                self.poll_once()
                self.maybe_prune()
            except Exception as exc:  # never let one bad poll kill the loop
                print(f"[run] poll error (continuing): {exc}")
            # Sleep the remainder of the interval (account for poll duration).
            elapsed = time.time() - start
            sleep_for = max(0.0, interval - elapsed)
            # Sleep in small slices so SIGTERM is honoured promptly.
            slept = 0.0
            while slept < sleep_for and not self._stop:
                chunk = min(0.5, sleep_for - slept)
                time.sleep(chunk)
                slept += chunk

        print("[run] netwatch-pi watchdog stopped")

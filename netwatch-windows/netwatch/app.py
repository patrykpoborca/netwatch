"""Application orchestration + CLI for netwatch-windows.

Implements the run loop (poll -> sample -> log -> push -> state machine -> event snapshot),
plus the CLI commands: run, snapshot, classify-latest, install-task, uninstall-task, and
run --repair.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections import deque
from typing import Any, Deque, Dict, List, Optional

from . import scheduler, snapshot, state, pktparse
from .checks import choose_active_adapter, detect_adapters
from .collector import Collector
from .config import Config, load_config
from .logstore import JsonlLogger, prune_event_folders, zip_event_folder
from .repair import run_repair_actions
from .runner import CommandErrorLog
from .sampler import collect_sample

# How many recent samples to retain in memory for recent_samples.jsonl / history checks.
HISTORY_MAXLEN = 60


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ensure_dirs(cfg: Config) -> None:
    os.makedirs(cfg.output_dir, exist_ok=True)
    os.makedirs(cfg.events_dir, exist_ok=True)


def _log(msg: str) -> None:
    """Lightweight stderr logger (does not depend on the JSONL store)."""
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    print(f"[netwatch {ts}] {msg}", file=sys.stderr, flush=True)


def _maybe_summarize_packets(folder: str) -> None:
    """If an optional packet parser is available, write tcpdump_summary-style summary."""
    if not pktparse.available():
        return
    pcap = os.path.join(folder, "pktmon_capture.pcapng")
    summary = pktparse.summarize_capture(pcap)
    if summary:
        try:
            with open(os.path.join(folder, "packet_summary.txt"), "w", encoding="utf-8") as fh:
                fh.write(summary)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# run
# ---------------------------------------------------------------------------

def cmd_run(cfg: Config, repair: bool = False) -> int:
    """Continuous watchdog loop. Never crashes the loop on a command failure."""
    _ensure_dirs(cfg)

    if repair and not cfg.repair_enabled:
        _log("--repair was passed but repair_enabled is false in config; refusing to repair.")
        _log("Continuing in logging-only mode.")
        repair = False

    logger = JsonlLogger(
        cfg.jsonl_log_path,
        max_mb=cfg.log_management.get("max_jsonl_mb", 50),
        max_rotated_files=cfg.log_management.get("max_rotated_jsonl_files", 5),
        gzip_rotated=cfg.log_management.get("gzip_rotated_jsonl", True),
    )
    collector = Collector(cfg)
    sm = state.StateMachine(
        failure_threshold_count=cfg.failure_threshold_count,
        event_cooldown_seconds=cfg.event_cooldown_seconds,
    )
    history: Deque[Dict[str, Any]] = deque(maxlen=HISTORY_MAXLEN)

    # Retention pass at startup, then periodically.
    _run_prune(cfg)
    prune_interval = float(cfg.log_management.get("prune_interval_seconds", 3600))
    prune_state = {"last": time.monotonic(), "interval": prune_interval}

    _log(
        f"Starting watchdog: poll={cfg.poll_interval_seconds}s "
        f"threshold={cfg.failure_threshold_count} cooldown={cfg.event_cooldown_seconds}s "
        f"repair={'ON' if repair else 'off'} collector={'on' if collector.enabled else 'off'}"
    )

    try:
        while True:
            cycle_start = time.monotonic()
            # The whole cycle is guarded: a persistent watchdog whose entire
            # purpose is to survive outages must never let one unexpected
            # exception (e.g. snapshot creation raising OSError when the disk
            # fills, or the state machine hitting bad data) kill the loop. This
            # mirrors the Pi watchdog's per-poll guard.
            try:
                _run_cycle(cfg, logger, collector, sm, history, repair, prune_state)
            except Exception as exc:  # noqa: BLE001 - last-resort loop guard
                _log(f"cycle error (continuing): {exc}")

            # Sleep the remainder of the poll interval.
            elapsed = time.monotonic() - cycle_start
            time.sleep(max(0.0, cfg.poll_interval_seconds - elapsed))
    except KeyboardInterrupt:
        _log("Interrupted; flushing collector buffer and exiting.")
        try:
            collector.flush_samples(CommandErrorLog())
        except Exception:  # noqa: BLE001
            pass
        return 0


def _run_cycle(
    cfg: Config,
    logger: JsonlLogger,
    collector: Collector,
    sm: "state.StateMachine",
    history: Deque[Dict[str, Any]],
    repair: bool,
    prune_state: Dict[str, float],
) -> None:
    """Run one poll/classify/log/push/event/prune cycle. Never raises.

    Extracted from :func:`cmd_run` so the loop body can be tested in isolation and
    so every step is individually guarded — no single failure (a raising snapshot,
    classifier, or retention pass) can escape and stop the watchdog.
    """
    error_log = CommandErrorLog()

    # 1. Collect a sample (best-effort; never raises).
    try:
        sample = collect_sample(cfg, error_log)
    except Exception as exc:  # noqa: BLE001 - last-resort guard
        _log(f"sample collection error (continuing): {exc}")
        sample = {"timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"), "error": str(exc)}

    # 2. Classify.
    hist_list = list(history)
    try:
        classification = state.classify(sample, hist_list)
    except Exception as exc:  # noqa: BLE001
        _log(f"classify error (continuing): {exc}")
        classification = "healthy"
    sample["classification"] = classification

    # 3. Write the JSONL line (must work even with no internet).
    try:
        logger.append(sample)
    except Exception as exc:  # noqa: BLE001
        _log(f"jsonl append error (continuing): {exc}")

    # 4. Best-effort push to the Pi collector (never blocks/crashes).
    try:
        collector.push_sample(sample, error_log)
    except Exception as exc:  # noqa: BLE001
        error_log.record_raw("collector.push_sample", str(exc))

    # 5. State machine decides whether to snapshot.
    try:
        # sm.update() advances last_event_time (starts the cooldown) as soon as it
        # decides an event should fire — before the snapshot is actually captured.
        # Capture the prior anchor so that if _handle_event fails we can roll the
        # cooldown back: otherwise a transient snapshot failure would burn the full
        # event_cooldown_seconds (300s default) with NO evidence captured, and the
        # next degraded cycles would be suppressed even though nothing was recorded.
        cooldown_anchor = sm.last_event_time
        should_event, reasons = sm.update(sample)
        if should_event:
            _log(f"EVENT triggered: {classification} :: {', '.join(reasons)}")
            try:
                _handle_event(cfg, classification, sample, hist_list, reasons, collector, repair)
            except Exception as exc:  # noqa: BLE001 - snapshot must not kill the loop
                sm.last_event_time = cooldown_anchor  # roll back so we retry the snapshot
                _log(f"event handling error (continuing; cooldown rolled back to retry): {exc}")
    except Exception as exc:  # noqa: BLE001 - state-machine failure must not kill the loop
        _log(f"event handling error (continuing): {exc}")

    history.append(sample)

    # 6. Periodic retention pass.
    now = time.monotonic()
    if (now - prune_state["last"]) >= prune_state["interval"]:
        try:
            _run_prune(cfg)
        except Exception as exc:  # noqa: BLE001
            _log(f"retention pass error (continuing): {exc}")
        prune_state["last"] = now


def _handle_event(
    cfg: Config,
    classification: str,
    sample: Dict[str, Any],
    history: List[Dict[str, Any]],
    reasons: List[str],
    collector: Collector,
    repair: bool,
) -> None:
    """Create an event snapshot (optionally with before/after repair) and push it."""
    error_log = CommandErrorLog()

    if repair:
        # Snapshot BEFORE repair.
        _log("Repair mode: taking BEFORE snapshot, then repairing, then AFTER snapshot.")
        before_folder = snapshot.create_snapshot(
            cfg, classification, sample, history, reasons, error_log=error_log,
        )
        _maybe_summarize_packets(before_folder)

        # Resolve adapter alias for the bounce.
        adapters = detect_adapters(error_log)
        active = choose_active_adapter(adapters, cfg.preferred_interface_alias)
        alias = active.name if active else cfg.preferred_interface_alias
        actions = run_repair_actions(cfg, alias, error_log)
        _log("Repair actions: " + "; ".join(actions))

        # Re-sample after repair to capture local_ip_after / gateway_mac_after.
        after_sample = collect_sample(cfg, error_log)
        after_folder = snapshot.create_snapshot(
            cfg,
            after_sample.get("classification", classification),
            after_sample,
            history + [sample],
            reasons,
            error_log=error_log,
            local_ip_after=after_sample.get("local_ipv4"),
            gateway_mac_after=after_sample.get("gateway_mac"),
        )
        _maybe_summarize_packets(after_folder)
        _push_event(cfg, collector, after_folder, after_sample.get("classification", classification), error_log)
        return

    # Logging-only event.
    folder = snapshot.create_snapshot(cfg, classification, sample, history, reasons, error_log=error_log)
    _maybe_summarize_packets(folder)
    _push_event(cfg, collector, folder, classification, error_log)


def _push_event(
    cfg: Config,
    collector: Collector,
    folder: str,
    classification: str,
    error_log: CommandErrorLog,
) -> None:
    """Push event summary (+ optional zip) to the collector, best-effort."""
    if not collector.enabled or not collector.push_events_enabled:
        return
    eid = os.path.basename(folder)
    summary_path = os.path.join(folder, "summary.json")
    summary: Dict[str, Any] = {}
    try:
        with open(summary_path, "r", encoding="utf-8") as fh:
            summary = json.load(fh)
    except (OSError, ValueError):
        pass
    manifest = snapshot.manifest_of(folder)
    try:
        collector.push_event(eid, classification, summary, manifest, error_log)
    except Exception as exc:  # noqa: BLE001
        error_log.record_raw("collector.push_event", str(exc))

    # Optionally push the zipped event if small enough.
    try:
        zip_path = zip_event_folder(folder)
        if zip_path:
            collector.push_event_zip(eid, zip_path, error_log)
            # Remove the temporary zip; the folder remains on disk.
            try:
                os.remove(zip_path)
            except OSError:
                pass
    except Exception as exc:  # noqa: BLE001
        error_log.record_raw("collector.push_event_zip", str(exc))


def _run_prune(cfg: Config) -> None:
    lm = cfg.log_management
    stats = prune_event_folders(
        cfg.events_dir,
        max_folders=lm.get("max_event_folders", 50),
        max_age_days=lm.get("max_event_age_days", 30),
        auto_zip=lm.get("auto_zip_event_folders", True),
        hard_cap_items=lm.get("hard_cap_event_items", 200),
    )
    if any(stats.values()):
        _log(f"retention pass: {stats}")


# ---------------------------------------------------------------------------
# snapshot (manual, even when healthy)
# ---------------------------------------------------------------------------

def cmd_snapshot(cfg: Config) -> int:
    """Immediately create a diagnostic snapshot regardless of health."""
    _ensure_dirs(cfg)
    error_log = CommandErrorLog()
    sample = collect_sample(cfg, error_log)
    classification = state.classify(sample, [])
    sample["classification"] = classification
    _log(f"Manual snapshot; current classification: {classification}")
    folder = snapshot.create_snapshot(cfg, classification, sample, [], reasons=[], error_log=error_log)
    _maybe_summarize_packets(folder)
    _log(f"Snapshot written to: {folder}")
    print(folder)
    return 0


# ---------------------------------------------------------------------------
# classify-latest
# ---------------------------------------------------------------------------

def _latest_event_folder(cfg: Config) -> Optional[str]:
    if not os.path.isdir(cfg.events_dir):
        return None
    candidates = []
    for name in os.listdir(cfg.events_dir):
        full = os.path.join(cfg.events_dir, name)
        if os.path.isdir(full):
            candidates.append((os.path.getmtime(full), full))
    if not candidates:
        return None
    candidates.sort()
    return candidates[-1][1]


def cmd_classify_latest(cfg: Config) -> int:
    """Read the latest event folder's summary.json and print the likely diagnosis."""
    folder = _latest_event_folder(cfg)
    if not folder:
        _log("No event folders found.")
        print("No events recorded yet.")
        return 1
    summary_path = os.path.join(folder, "summary.json")
    try:
        with open(summary_path, "r", encoding="utf-8") as fh:
            summary = json.load(fh)
    except (OSError, ValueError) as exc:
        _log(f"Could not read summary.json: {exc}")
        return 1
    print(f"Latest event: {os.path.basename(folder)}")
    print(f"Classification: {summary.get('classification')}")
    print(f"\n{summary.get('plain_english', '')}\n")
    findings = summary.get("suspicious_findings") or []
    if findings:
        print("Suspicious findings:")
        for f in findings:
            print(f"  - {f}")
    steps = summary.get("recommended_next_steps") or []
    if steps:
        print("\nRecommended next steps:")
        for s in steps:
            print(f"  - {s}")
    return 0


# ---------------------------------------------------------------------------
# install-task / uninstall-task
# ---------------------------------------------------------------------------

def cmd_install_task(cfg: Config, run_as_system: bool) -> int:
    error_log = CommandErrorLog()
    ps1 = scheduler.install_task(cfg, run_as_system=run_as_system, error_log=error_log)
    _log(f"Wrote {ps1} and attempted to register the scheduled task '{scheduler.TASK_NAME}'.")
    if error_log:
        _log("Note: registration may require an elevated Windows shell. Run the .ps1 as Administrator if needed.")
    print(ps1)
    return 0


def cmd_uninstall_task(cfg: Config) -> int:
    error_log = CommandErrorLog()
    ps1 = scheduler.uninstall_task(error_log=error_log)
    _log(f"Wrote {ps1} and attempted to unregister the scheduled task '{scheduler.TASK_NAME}'.")
    print(ps1)
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="netwatch_windows.py",
        description="Windows Ethernet Watchdog - logging-first network diagnostics.",
    )
    p.add_argument("--config", help="Path to config.json (defaults to ./config.json).", default=None)
    sub = p.add_subparsers(dest="command", required=True)

    run_p = sub.add_parser("run", help="Run the continuous watchdog.")
    run_p.add_argument(
        "--repair",
        action="store_true",
        help="Allow manual repair actions on event (requires repair_enabled in config).",
    )

    sub.add_parser("snapshot", help="Create a diagnostic snapshot immediately, even if healthy.")
    sub.add_parser("classify-latest", help="Print the diagnosis from the most recent event folder.")

    inst = sub.add_parser("install-task", help="Install the Windows Scheduled Task.")
    inst.add_argument(
        "--system",
        action="store_true",
        help="Run the task as SYSTEM (default: current user, highest privileges).",
    )
    sub.add_parser("uninstall-task", help="Remove the Windows Scheduled Task.")

    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    cfg = load_config(args.config)

    if args.command == "run":
        return cmd_run(cfg, repair=getattr(args, "repair", False))
    if args.command == "snapshot":
        return cmd_snapshot(cfg)
    if args.command == "classify-latest":
        return cmd_classify_latest(cfg)
    if args.command == "install-task":
        return cmd_install_task(cfg, run_as_system=getattr(args, "system", False))
    if args.command == "uninstall-task":
        return cmd_uninstall_task(cfg)

    _log(f"Unknown command: {args.command}")
    return 2

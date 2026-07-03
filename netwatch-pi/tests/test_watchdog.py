"""Watchdog state-machine tests (stdlib unittest).

Covers the ``windows_unreachable_from_pi`` once-per-episode latch: a desktop
that is merely asleep/off must produce exactly ONE lower-severity event per
down-episode — not a fresh snapshot (with a 60s tcpdump) at every cooldown
expiry for the whole night — while real Pi-side failures keep triggering
normally.
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from netwatch.config import Config, default_config_dict  # noqa: E402
from netwatch.watchdog import Watchdog  # noqa: E402


def _cfg(tmpdir: str, threshold: int = 3, cooldown: float = 0.0) -> Config:
    raw = default_config_dict()
    raw["output_dir"] = tmpdir
    raw["jsonl_log_path"] = os.path.join(tmpdir, "netwatch-pi.jsonl")
    raw["failure_threshold_count"] = threshold
    raw["event_cooldown_seconds"] = cooldown
    return Config(raw, path=None)


class TestWindowsUnreachableLatch(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        # cooldown=0 so the latch (not the cooldown) is what suppresses repeats.
        self.wd = Watchdog(_cfg(self._tmp.name, threshold=3, cooldown=0.0))
        self.triggered = []
        self.wd._trigger_event = lambda classification, sample: self.triggered.append(
            classification
        )

    def tearDown(self):
        self._tmp.cleanup()

    def _poll_windows_down(self, times: int = 1):
        for _ in range(times):
            self.wd._update_state(
                {"windows_ping_ok": False}, "windows_unreachable_from_pi"
            )

    def _poll_healthy(self):
        self.wd._update_state(
            {"windows_ping_ok": True, "gateway_mac": "aa:bb:cc:dd:ee:ff"}, "healthy"
        )

    def test_single_event_per_down_episode(self):
        # Threshold polls -> exactly one event.
        self._poll_windows_down(3)
        self.assertEqual(self.triggered, ["windows_unreachable_from_pi"])
        # Desktop stays down for many more polls: NO re-trigger even though
        # cooldown is 0 (previously this re-fired at every cooldown expiry).
        self._poll_windows_down(50)
        self.assertEqual(len(self.triggered), 1)

    def test_latch_rearms_after_recovery(self):
        self._poll_windows_down(3)
        self._poll_healthy()  # Windows back -> latch cleared
        self._poll_windows_down(3)
        self.assertEqual(self.triggered, ["windows_unreachable_from_pi"] * 2)

    def test_real_pi_failure_not_suppressed_by_latch(self):
        # Fire (and latch) the Windows-down event first.
        self._poll_windows_down(3)
        self.assertEqual(len(self.triggered), 1)
        # A genuine Pi-side failure while Windows is still down must still
        # count and trigger normally.
        for _ in range(3):
            self.wd._update_state(
                {"windows_ping_ok": False, "gateway_ping_ok": False},
                "gateway_unreachable",
            )
        self.assertEqual(
            self.triggered, ["windows_unreachable_from_pi", "gateway_unreachable"]
        )

    def test_below_threshold_does_not_trigger(self):
        self._poll_windows_down(2)
        self.assertEqual(self.triggered, [])


if __name__ == "__main__":
    unittest.main()

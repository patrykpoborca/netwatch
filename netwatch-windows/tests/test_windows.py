"""Regression tests for netwatch-windows (stdlib unittest only).

Covers the wave-2 fixes:
  * ``runner.ps_quote`` — PowerShell single-quote escaping (command-injection guard).
  * ``app._run_cycle`` — the watchdog cycle must never propagate an exception
    (loop-crash robustness), even when sampling / classification / event handling
    all fail.
  * ``collector.Collector`` — client-side sample batching + host_label stamping.

Run with:  python -m unittest discover -s netwatch-windows/tests
       or:  python -m pytest netwatch-windows/tests
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest

# Make the netwatch package importable regardless of CWD.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from netwatch import app  # noqa: E402
from netwatch.collector import Collector  # noqa: E402
from netwatch.config import Config, default_config_dict  # noqa: E402
from netwatch.logstore import JsonlLogger  # noqa: E402
from netwatch.runner import CommandErrorLog, ps_quote  # noqa: E402
from netwatch import state  # noqa: E402


class TestPsQuote(unittest.TestCase):
    def test_plain_value_unchanged(self):
        self.assertEqual(ps_quote("Ethernet"), "Ethernet")
        self.assertEqual(ps_quote("192.168.4.1"), "192.168.4.1")

    def test_single_quote_is_doubled(self):
        # A lone single quote is the ONLY metacharacter in a PS single-quoted
        # string; doubling it keeps the payload inside the literal.
        self.assertEqual(ps_quote("a'b"), "a''b")

    def test_injection_payload_neutralized(self):
        payload = "Ethernet'; Remove-Item C:\\ -Recurse; '"
        quoted = ps_quote(payload)
        # The real invariant: after removing every doubled quote (''), NO bare
        # single quote remains — so nothing can close the surrounding '...'
        # literal and the whole payload stays inert data inside the string.
        self.assertNotIn("'", quoted.replace("''", ""))
        # Re-embedded, the quotes are balanced (even count).
        embedded = f"'{quoted}'"
        self.assertEqual(embedded.count("'") % 2, 0)

    def test_non_string_coerced(self):
        self.assertEqual(ps_quote(2), "2")
        self.assertEqual(ps_quote(None), "None")

    def test_typographic_quotes_normalized_and_escaped(self):
        # PowerShell treats U+2018/U+2019/U+201A/U+201B as single-quote string
        # delimiters, so they must be folded to ASCII ' and doubled, or an
        # attacker could close a '...' literal with a smart quote and inject code.
        for smart in ("‘", "’", "‚", "‛"):
            with self.subTest(smart=smart):
                out = ps_quote(f"a{smart}b")
                self.assertEqual(out, "a''b")
                self.assertTrue(out.isascii())
                self.assertNotIn("'", out.replace("''", ""))

    def test_smart_quote_injection_payload_neutralized(self):
        payload = "Ethernet’; Remove-Item C:\\ -Recurse; ‘"
        out = ps_quote(payload)
        self.assertTrue(out.isascii())
        self.assertNotIn("'", out.replace("''", ""))  # nothing can close '...'
        self.assertEqual(f"'{out}'".count("'") % 2, 0)


def _temp_cfg(tmpdir: str) -> Config:
    raw = default_config_dict()
    raw["output_dir"] = tmpdir
    raw["jsonl_log_path"] = os.path.join(tmpdir, "netwatch-windows.jsonl")
    raw["poll_interval_seconds"] = 0  # not used by _run_cycle directly
    return Config(raw=raw)


class TestRunCycleRobustness(unittest.TestCase):
    """A single bad cycle must never escape and stop the watchdog loop."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmpdir = self._tmp.name
        self.cfg = _temp_cfg(self.tmpdir)
        self.logger = JsonlLogger(self.cfg.jsonl_log_path)
        self.collector = Collector(self.cfg)  # disabled by default
        self.history = __import__("collections").deque(maxlen=60)
        self.prune_state = {"last": 1e18, "interval": 1e18}  # never prune during test

    def tearDown(self):
        self._tmp.cleanup()

    def _sm(self, threshold=1):
        return state.StateMachine(failure_threshold_count=threshold, event_cooldown_seconds=0)

    def test_sample_collection_raises_does_not_propagate(self):
        orig = app.collect_sample
        app.collect_sample = lambda cfg, err: (_ for _ in ()).throw(RuntimeError("boom"))
        try:
            # Must not raise.
            app._run_cycle(self.cfg, self.logger, self.collector, self._sm(),
                           self.history, False, self.prune_state)
        finally:
            app.collect_sample = orig
        # A sample (with error) was still appended to history.
        self.assertEqual(len(self.history), 1)
        self.assertIn("error", self.history[-1])

    def test_event_handler_raises_does_not_propagate(self):
        # Force a degraded sample so the (threshold=1) state machine fires an event,
        # then make the event handler blow up. The cycle must swallow it.
        degraded = {"timestamp": "t", "link_up": False}
        orig_sample = app.collect_sample
        orig_handle = app._handle_event
        app.collect_sample = lambda cfg, err: dict(degraded)
        app._handle_event = lambda *a, **k: (_ for _ in ()).throw(OSError("disk full"))
        try:
            app._run_cycle(self.cfg, self.logger, self.collector, self._sm(threshold=1),
                           self.history, False, self.prune_state)
        finally:
            app.collect_sample = orig_sample
            app._handle_event = orig_handle
        # Loop survived; sample recorded.
        self.assertEqual(len(self.history), 1)

    def test_prune_raises_does_not_propagate(self):
        # Make the retention pass due, and make it raise.
        self.prune_state = {"last": 0.0, "interval": 0.0}
        orig_sample = app.collect_sample
        orig_prune = app._run_prune
        app.collect_sample = lambda cfg, err: {"timestamp": "t", "link_up": True,
                                               "local_ipv4": "192.168.4.50",
                                               "default_gateway": "192.168.4.1",
                                               "gateway_ping_ok": True,
                                               "internet_ping_ok": True}
        app._run_prune = lambda cfg: (_ for _ in ()).throw(RuntimeError("prune boom"))
        try:
            app._run_cycle(self.cfg, self.logger, self.collector, self._sm(threshold=99),
                           self.history, False, self.prune_state)
        finally:
            app.collect_sample = orig_sample
            app._run_prune = orig_prune


class TestConfigNullSections(unittest.TestCase):
    """A config that explicitly nulls log_management/collector must not crash."""

    def test_null_log_management_returns_empty_dict(self):
        raw = default_config_dict()
        raw["log_management"] = None  # user set it to null in config.json
        cfg = Config(raw=raw)
        self.assertEqual(cfg.log_management, {})
        # The exact call sites cmd_run uses must not raise.
        self.assertEqual(cfg.log_management.get("prune_interval_seconds", 3600), 3600)

    def test_null_collector_returns_empty_dict(self):
        raw = default_config_dict()
        raw["collector"] = None
        cfg = Config(raw=raw)
        self.assertEqual(cfg.collector, {})
        # Collector(cfg) reads cfg.collector heavily; must construct cleanly.
        c = Collector(cfg)
        self.assertFalse(c.enabled)


class TestCollectorBatching(unittest.TestCase):
    def _cfg(self):
        raw = default_config_dict()
        raw["collector"]["enabled"] = True
        raw["collector"]["base_url"] = "http://127.0.0.1:1"
        raw["collector"]["sample_batch_size"] = 3
        return Config(raw=raw)

    def test_disabled_collector_is_noop(self):
        c = Collector(Config(raw=default_config_dict()))  # enabled=False
        c.push_sample({"x": 1}, CommandErrorLog())
        self.assertEqual(len(c._sample_buffer), 0)

    def test_batches_and_stamps_host_label(self):
        c = Collector(self._cfg())
        posted = []
        c._post_json = lambda path, body, err: posted.append((path, body)) or True
        err = CommandErrorLog()
        for _ in range(3):
            c.push_sample({"v": 1}, err)  # 3rd triggers a flush at batch_size=3
        self.assertEqual(len(posted), 1)
        path, body = posted[0]
        self.assertEqual(path, "/ingest/samples")
        self.assertEqual(len(body["samples"]), 3)
        # host_label stamped on every buffered sample.
        for s in body["samples"]:
            self.assertEqual(s["host_label"], c.host_label)
        # Buffer drained after flush.
        self.assertEqual(len(c._sample_buffer), 0)


if __name__ == "__main__":
    unittest.main()

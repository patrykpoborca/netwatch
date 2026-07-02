"""Config-loading robustness tests (stdlib unittest).

The stated contract is "never crash on a missing/partial config — always
degrade to defaults". An explicit ``null`` for a dict-valued section
(``log_management`` / ``collector`` / ``targets``) used to survive the
deep-merge as ``None`` and crash the watchdog at startup (systemd then
crash-loops it every 5s). These tests pin the normalization that restores the
section defaults instead.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from netwatch import config as config_mod  # noqa: E402
from netwatch.watchdog import Watchdog  # noqa: E402


class TestNullSectionsDegradeToDefaults(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self._tmp.cleanup()

    def _load(self, user_cfg: dict):
        path = os.path.join(self._tmp.name, "config.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(user_cfg, fh)
        return config_mod.load_config(path)

    def test_null_sections_restored_to_defaults(self):
        cfg = self._load(
            {"log_management": None, "collector": None, "targets": None}
        )
        self.assertIsInstance(cfg.log_management, dict)
        self.assertIsInstance(cfg.collector, dict)
        self.assertIsInstance(cfg.targets, dict)
        # The exact keys the watchdog/collector index directly must be present.
        self.assertIn("max_jsonl_mb", cfg.log_management)
        self.assertIn("incoming_dir", cfg.collector)
        self.assertIn("internet_ips", cfg.targets)

    def test_watchdog_constructs_with_nulled_log_management(self):
        cfg = self._load(
            {
                "log_management": None,
                "output_dir": self._tmp.name,
                "jsonl_log_path": os.path.join(self._tmp.name, "x.jsonl"),
            }
        )
        # Previously: TypeError ('NoneType' is not subscriptable) at startup.
        wd = Watchdog(cfg)
        self.assertGreater(wd.appender.max_bytes, 0)

    def test_partial_section_still_merged(self):
        cfg = self._load({"log_management": {"max_jsonl_mb": 7}})
        self.assertEqual(cfg.log_management["max_jsonl_mb"], 7)
        # Other keys backfilled from defaults.
        self.assertEqual(cfg.log_management["max_rotated_jsonl_files"], 5)

    def test_scalar_null_still_respected(self):
        # gateway_ip_override: null is a legitimate explicit value and must NOT
        # be "restored" to anything.
        cfg = self._load({"gateway_ip_override": None})
        self.assertIsNone(cfg["gateway_ip_override"])


if __name__ == "__main__":
    unittest.main()

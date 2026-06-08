"""Configuration loading and defaults for netwatch-windows.

The on-disk schema matches the technical spec exactly (``config.json``). This module
adds two operator-requested sections that have sane defaults so existing configs keep
working without modification:

* ``log_management`` - JSONL rotation + event-folder retention (log-swell control).
* ``collector``      - optional best-effort push to a central Raspberry Pi log host.

Unknown keys in the user's config are preserved and merged over the defaults so the
app never crashes on a slightly-out-of-date config file.
"""

from __future__ import annotations

import copy
import json
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Default configuration
# ---------------------------------------------------------------------------

DEFAULT_CONFIG: Dict[str, Any] = {
    # --- core spec keys -----------------------------------------------------
    "host_label": "gaming-desktop",
    "preferred_interface_alias": "Ethernet",
    "raspberry_pi_ip": "192.168.4.25",
    "gateway_ip_override": None,
    "poll_interval_seconds": 5,
    "failure_threshold_count": 3,
    "event_cooldown_seconds": 300,
    "packet_capture_seconds": 60,
    "output_dir": "C:\\NetworkSnapshots",
    "jsonl_log_path": "C:\\NetworkSnapshots\\netwatch-windows.jsonl",
    "targets": {
        "internet_ips": ["1.1.1.1", "8.8.8.8"],
        "dns_names": ["google.com", "cloudflare.com"],
    },
    "enable_pktmon_capture": True,
    "enable_netsh_trace_fallback": True,
    "repair_enabled": False,
    # --- log-swell control (operator requested) ----------------------------
    "log_management": {
        # JSONL rotation by size
        "max_jsonl_mb": 50,
        "max_rotated_jsonl_files": 5,
        "gzip_rotated_jsonl": True,
        # Event folder retention
        "max_event_folders": 50,
        "max_event_age_days": 30,
        # Auto-zip old event folders once over the soft cap; prune beyond hard cap.
        "auto_zip_event_folders": True,
        # Hard cap so disk never grows unbounded (zips + folders counted together).
        "hard_cap_event_items": 200,
        # How often (seconds) the retention pass runs during `run` (also at startup).
        "prune_interval_seconds": 3600,
    },
    # --- optional central collector (Raspberry Pi) --------------------------
    "collector": {
        "enabled": False,
        "base_url": "http://192.168.4.25:8787",
        "auth_token": None,
        "push_samples": True,
        "push_events": True,
        # Best-effort networking knobs.
        "timeout_seconds": 3,
        "sample_batch_size": 10,
        "max_push_event_mb": 5,
    },
}


@dataclass
class Config:
    """Typed-ish wrapper around the merged config dict.

    Attribute access is provided for the hot-path fields used throughout the code;
    the raw merged dict is always available via ``.raw`` for anything else.
    """

    raw: Dict[str, Any] = field(default_factory=dict)

    # --- core ---------------------------------------------------------------
    @property
    def host_label(self) -> str:
        return self.raw["host_label"]

    @property
    def preferred_interface_alias(self) -> Optional[str]:
        return self.raw.get("preferred_interface_alias")

    @property
    def raspberry_pi_ip(self) -> Optional[str]:
        return self.raw.get("raspberry_pi_ip")

    @property
    def gateway_ip_override(self) -> Optional[str]:
        return self.raw.get("gateway_ip_override")

    @property
    def poll_interval_seconds(self) -> float:
        return float(self.raw["poll_interval_seconds"])

    @property
    def failure_threshold_count(self) -> int:
        return int(self.raw["failure_threshold_count"])

    @property
    def event_cooldown_seconds(self) -> float:
        return float(self.raw["event_cooldown_seconds"])

    @property
    def packet_capture_seconds(self) -> int:
        return int(self.raw["packet_capture_seconds"])

    @property
    def output_dir(self) -> str:
        return self.raw["output_dir"]

    @property
    def jsonl_log_path(self) -> str:
        return self.raw["jsonl_log_path"]

    @property
    def internet_ips(self) -> List[str]:
        return list(self.raw.get("targets", {}).get("internet_ips", []))

    @property
    def dns_names(self) -> List[str]:
        return list(self.raw.get("targets", {}).get("dns_names", []))

    @property
    def enable_pktmon_capture(self) -> bool:
        return bool(self.raw.get("enable_pktmon_capture", True))

    @property
    def enable_netsh_trace_fallback(self) -> bool:
        return bool(self.raw.get("enable_netsh_trace_fallback", True))

    @property
    def repair_enabled(self) -> bool:
        return bool(self.raw.get("repair_enabled", False))

    # --- sections -----------------------------------------------------------
    @property
    def log_management(self) -> Dict[str, Any]:
        return self.raw.get("log_management", {})

    @property
    def collector(self) -> Dict[str, Any]:
        return self.raw.get("collector", {})

    # --- derived paths ------------------------------------------------------
    @property
    def events_dir(self) -> str:
        return os.path.join(self.output_dir, "events")


def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    """Recursively merge ``override`` onto a copy of ``base``."""
    result = copy.deepcopy(base)
    for key, value in (override or {}).items():
        if (
            key in result
            and isinstance(result[key], dict)
            and isinstance(value, dict)
        ):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def default_config_dict() -> Dict[str, Any]:
    """Return a deep copy of the default configuration."""
    return copy.deepcopy(DEFAULT_CONFIG)


def load_config(path: Optional[str] = None) -> Config:
    """Load and merge configuration from ``path`` (defaults applied for any missing keys).

    If ``path`` is None, look for ``config.json`` next to the entrypoint / CWD. A missing
    file is not fatal: defaults are used so the watchdog can still run.
    """
    user_cfg: Dict[str, Any] = {}
    if path is None:
        # Look beside the package first, then CWD.
        candidates = [
            os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config.json"),
            os.path.join(os.getcwd(), "config.json"),
        ]
        for cand in candidates:
            if os.path.isfile(cand):
                path = cand
                break

    if path and os.path.isfile(path):
        with open(path, "r", encoding="utf-8") as fh:
            user_cfg = json.load(fh)

    merged = _deep_merge(DEFAULT_CONFIG, user_cfg)
    return Config(raw=merged)

"""Configuration loading and defaults for netwatch-pi.

The authoritative on-disk config lives at ``/etc/netwatch-pi/config.json`` (the
path is overridable via ``--config``). This module loads that JSON, fills in any
missing keys with sane defaults, and exposes a small dataclass-like accessor.

Design goals:
  * Never crash on a missing/partial config — always degrade to defaults.
  * Keep the schema exactly matching the spec, with two additive sections the
    user explicitly asked for: ``log_management`` (SD-card swell control) and
    ``collector`` (the HTTP log-collection host).
"""

from __future__ import annotations

import copy
import json
import os
from typing import Any, Dict

# Default config path per the spec.
DEFAULT_CONFIG_PATH = "/etc/netwatch-pi/config.json"


# The full default configuration. Anything the user omits from their config.json
# is backfilled from here, so the app always has a complete, valid config.
DEFAULTS: Dict[str, Any] = {
    # --- Core watchdog (exact schema from the spec) ---
    "host_label": "raspberry-pi-wifi",
    "preferred_interface": "wlan0",
    "windows_desktop_ip": "192.168.4.50",
    "gateway_ip_override": None,
    "poll_interval_seconds": 5,
    "failure_threshold_count": 3,
    "event_cooldown_seconds": 300,
    "packet_capture_seconds": 60,
    "output_dir": "/var/log/netwatch-pi",
    "jsonl_log_path": "/var/log/netwatch-pi/netwatch-pi.jsonl",
    "targets": {
        "internet_ips": ["1.1.1.1", "8.8.8.8"],
        "dns_names": ["google.com", "cloudflare.com"],
    },
    "enable_tcpdump_capture": True,

    # --- SD-card / log-swell control (user-requested) ---
    "log_management": {
        # Rotate the JSONL when it grows past this size, gzip it, keep N rotations.
        "max_jsonl_mb": 50,
        "max_rotated_jsonl_files": 5,
        # Event-folder retention: cap by count and age, zip oldest, hard-prune.
        "max_event_folders": 50,
        "max_event_age_days": 30,
        # How often (seconds) the run loop performs a retention/prune pass.
        "prune_interval_seconds": 3600,
    },

    # --- Collection host / HTTP log server (user-requested) ---
    "collector": {
        "enabled": True,
        "bind_host": "0.0.0.0",
        "bind_port": 8787,
        # If set, every endpoint requires "Authorization: Bearer <token>".
        # If null, the server is open and trusts the LAN (documented in README).
        "auth_token": None,
        "incoming_dir": "/var/log/netwatch-pi/incoming",
        # Hard cap on the total size of incoming/ pushed logs to protect the SD card.
        "max_incoming_mb": 500,
    },
}


class Config:
    """Thin wrapper around the merged config dict with attribute-style access.

    Use ``cfg["key"]`` for top-level keys and the helper properties for the
    nested sections. The raw merged dict is available via :attr:`data`.
    """

    def __init__(self, data: Dict[str, Any], path: str | None = None):
        self.data = data
        self.path = path

    def __getitem__(self, key: str) -> Any:
        return self.data[key]

    def get(self, key: str, default: Any = None) -> Any:
        return self.data.get(key, default)

    # Convenience accessors for the nested sections.
    @property
    def targets(self) -> Dict[str, Any]:
        return self.data["targets"]

    @property
    def log_management(self) -> Dict[str, Any]:
        return self.data["log_management"]

    @property
    def collector(self) -> Dict[str, Any]:
        return self.data["collector"]

    @property
    def events_dir(self) -> str:
        return os.path.join(self.data["output_dir"], "events")


def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    """Recursively merge ``override`` onto a deep copy of ``base``.

    Nested dicts are merged key-by-key so a user who only overrides
    ``log_management.max_jsonl_mb`` still gets every other default.
    """
    result = copy.deepcopy(base)
    for key, value in override.items():
        if (
            key in result
            and isinstance(result[key], dict)
            and isinstance(value, dict)
        ):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result


def load_config(path: str | None = None) -> Config:
    """Load config from ``path`` (default ``/etc/netwatch-pi/config.json``).

    Missing file or unreadable/invalid JSON degrades gracefully to the full
    defaults — the watchdog must never refuse to start just because config is
    absent. Any user-supplied keys are deep-merged over the defaults.
    """
    resolved = path or DEFAULT_CONFIG_PATH
    user_data: Dict[str, Any] = {}

    try:
        with open(resolved, "r", encoding="utf-8") as fh:
            user_data = json.load(fh)
        if not isinstance(user_data, dict):
            user_data = {}
    except FileNotFoundError:
        # No config on disk yet — fall back entirely to defaults.
        user_data = {}
    except (json.JSONDecodeError, OSError):
        # Corrupt/unreadable config — still start with defaults rather than crash.
        user_data = {}

    merged = _deep_merge(DEFAULTS, user_data)
    return Config(merged, path=resolved)


def default_config_dict() -> Dict[str, Any]:
    """Return a deep copy of the full default config (used to write a sample)."""
    return copy.deepcopy(DEFAULTS)

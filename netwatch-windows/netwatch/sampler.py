"""Builds a single lightweight health sample each polling cycle.

The output dict matches the spec's sample schema exactly (plus a few extra counter
fields that are harmless additions used by storm heuristics). All work is delegated to
:mod:`netwatch.checks`, and every command failure is funneled into the shared
:class:`CommandErrorLog` so the loop never crashes.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from . import checks
from .config import Config
from .runner import CommandErrorLog


def _local_timestamp() -> str:
    """Return an ISO-8601 timestamp with the local UTC offset (e.g. ...-05:00).

    The spec's example uses a local offset; using ``astimezone()`` with no argument
    attaches the system's local timezone, so paired Windows/Pi logs can be aligned.
    """
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="milliseconds")


def collect_sample(cfg: Config, error_log: Optional[CommandErrorLog] = None) -> Dict[str, Any]:
    """Run all seven checks and return one sample dict (spec schema)."""
    if error_log is None:
        error_log = CommandErrorLog()

    # Check 1: adapters + choose the active one.
    adapters = checks.detect_adapters(error_log)
    active = checks.choose_active_adapter(adapters, cfg.preferred_interface_alias)
    alias = active.name if active else cfg.preferred_interface_alias

    # Check 2: link + IP config + statistics.
    link = checks.get_link_state(alias, error_log)
    ipcfg = checks.get_ip_configuration(alias, error_log)
    stats = checks.get_adapter_statistics(alias, error_log)

    # Determine gateway (override beats auto-detection).
    gateway = cfg.gateway_ip_override or ipcfg.get("default_gateway")

    # Checks 3-7.
    gw_ok = checks.gateway_ping(gateway, error_log)
    inet_ok = checks.internet_ping(cfg.internet_ips, error_log)
    dns_ok = checks.dns_resolution_ok(cfg.dns_names, error_log)
    pi_ok = checks.pi_ping(cfg.raspberry_pi_ip, error_log)
    gw_mac = checks.gateway_mac(gateway, error_log)

    suspicious_adapters = [
        {
            "name": a.name,
            "description": a.interface_description,
            "status": a.status,
            "reasons": a.suspicious_reasons,
        }
        for a in adapters
        if a.is_suspicious
    ]

    sample: Dict[str, Any] = {
        "timestamp": _local_timestamp(),
        "host_label": cfg.host_label,
        "os": "Windows",
        "interface_alias": alias,
        "interface_description": link.get("interface_description"),
        "local_ipv4": ipcfg.get("local_ipv4"),
        "default_gateway": gateway,
        "dns_servers": ipcfg.get("dns_servers", []),
        "link_up": link.get("link_up", False),
        "link_speed": link.get("link_speed"),
        "gateway_ping_ok": gw_ok,
        "internet_ping_ok": inet_ok,
        "dns_resolution_ok": dns_ok,
        "pi_ping_ok": pi_ok,
        "gateway_mac": gw_mac,
        "adapter_rx_bytes": stats.get("adapter_rx_bytes", 0),
        "adapter_tx_bytes": stats.get("adapter_tx_bytes", 0),
        "adapter_rx_errors": stats.get("adapter_rx_errors", 0),
        "adapter_tx_errors": stats.get("adapter_tx_errors", 0),
        # Extra (non-spec) fields used by storm heuristics / richer diagnosis.
        "adapter_rx_discards": stats.get("adapter_rx_discards", 0),
        "adapter_tx_discards": stats.get("adapter_tx_discards", 0),
        "suspicious_adapters": suspicious_adapters,
        "classification": "healthy",  # filled in by the state machine
    }
    return sample

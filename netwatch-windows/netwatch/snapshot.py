"""Event snapshot capture: writes every diagnostic file the spec lists.

Creates ``events/YYYY-MM-DD_HH-mm-ss_windows_<classification>/`` and fills it with all
the PowerShell/cmd dumps, event-log captures, a packet capture (pktmon preferred,
netsh trace fallback), ``recent_samples.jsonl``, ``summary.json`` and ``command_errors.json``.

Everything is best-effort: a missing command writes an empty/placeholder file and records
the failure into ``command_errors.json`` instead of crashing. Packet captures are bounded
by ``packet_capture_seconds`` to keep file sizes small.
"""

from __future__ import annotations

import json
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

from . import state
from .config import Config
from .runner import CommandErrorLog, run_cmd, run_powershell


# Map of output filename -> (kind, command). kind is "ps" or "cmd".
# These mirror the spec's "Commands to Capture" and "Event Snapshot Folder" sections.
_TEXT_CAPTURES: List[Dict[str, Any]] = [
    # Basic state (cmd)
    {"file": "ipconfig_all.txt", "kind": "cmd", "args": ["ipconfig", "/all"]},
    {"file": "route_print.txt", "kind": "cmd", "args": ["route", "print"]},
    {"file": "arp_a.txt", "kind": "cmd", "args": ["arp", "-a"]},
    {"file": "active_connections.txt", "kind": "cmd", "args": ["netstat", "-ano"]},
    # PowerShell network state
    {"file": "get_net_adapter.txt", "kind": "ps", "script": "Get-NetAdapter | Format-List *"},
    {
        "file": "get_net_adapter_statistics.txt",
        "kind": "ps",
        "script": "Get-NetAdapterStatistics | Format-List *",
    },
    {
        "file": "get_net_adapter_advanced_property.txt",
        "kind": "ps",
        "script": "Get-NetAdapterAdvancedProperty | Format-List *",
    },
    {
        "file": "get_net_ip_configuration.txt",
        "kind": "ps",
        "script": "Get-NetIPConfiguration | Format-List *",
    },
    {
        "file": "get_net_neighbor.txt",
        "kind": "ps",
        "script": "Get-NetNeighbor | Format-Table -AutoSize | Out-String -Width 4096",
    },
    {
        "file": "dns_client_server_address.txt",
        "kind": "ps",
        "script": "Get-DnsClientServerAddress | Format-List *",
    },
    {"file": "dns_client_cache.txt", "kind": "ps", "script": "Get-DnsClientCache | Out-String -Width 4096"},
    # Suspicious sharing / bridge state (extra useful dumps; not separately named in the
    # snapshot file list but valuable for diagnosis).
    {
        "file": "net_route.txt",
        "kind": "ps",
        "script": "Get-NetRoute | Format-Table -AutoSize | Out-String -Width 4096",
    },
    {"file": "net_ip_interface.txt", "kind": "ps", "script": "Get-NetIPInterface | Format-List *"},
    {
        "file": "net_adapter_binding.txt",
        "kind": "ps",
        "script": "Get-NetAdapterBinding | Format-Table -AutoSize | Out-String -Width 4096",
    },
    {
        "file": "net_connection_profile.txt",
        "kind": "ps",
        "script": "Get-NetConnectionProfile | Format-List *",
    },
    {
        "file": "shared_access_service.txt",
        "kind": "ps",
        "script": "Get-Service SharedAccess -ErrorAction SilentlyContinue | Format-List *",
    },
    {
        "file": "bridge_adapters.txt",
        "kind": "ps",
        "script": (
            "Get-NetAdapter | Where-Object { $_.Name -like '*Bridge*' -or "
            "$_.InterfaceDescription -like '*Bridge*' } | Format-List *"
        ),
    },
    {
        "file": "time_sync_status.txt",
        "kind": "cmd",
        "args": ["w32tm", "/query", "/status"],
    },
]


def event_id(classification: str, when: Optional[datetime] = None) -> str:
    """Build the ``YYYY-MM-DD_HH-mm-ss_windows_<classification>`` event id (local time)."""
    when = when or datetime.now()
    return f"{when.strftime('%Y-%m-%d_%H-%M-%S')}_windows_{classification}"


def _write(path: str, content: str) -> None:
    try:
        with open(path, "w", encoding="utf-8", errors="replace") as fh:
            fh.write(content or "")
    except OSError:
        pass


def capture_text_files(folder: str, error_log: CommandErrorLog) -> None:
    """Run each diagnostic command and write its output to the snapshot folder."""
    for cap in _TEXT_CAPTURES:
        out_path = os.path.join(folder, cap["file"])
        if cap["kind"] == "cmd":
            res = run_cmd(cap["args"], error_log=error_log, timeout=45, label=" ".join(cap["args"]))
        else:
            res = run_powershell(
                cap["script"], error_log=error_log, timeout=60, label=cap["script"][:80]
            )
        body = res.stdout
        if not res.ok and res.error:
            body = (body or "") + f"\n[netwatch] command error: {res.error}\n"
        _write(out_path, body)


def capture_event_logs(folder: str, error_log: CommandErrorLog) -> None:
    """Capture network-adjacent System events and broad System events."""
    network_script = (
        "Get-WinEvent -LogName System -MaxEvents 300 -ErrorAction SilentlyContinue | "
        "Where-Object { $_.ProviderName -match "
        "'Tcpip|Dhcp|DNS|Netwtw|e1|Realtek|NDIS|WLAN|NetworkProfile|Kernel-Network' } | "
        "Format-List * | Out-String -Width 4096"
    )
    res = run_powershell(network_script, error_log=error_log, timeout=90, label="WinEvent System (network)")
    _write(os.path.join(folder, "network_eventlog_system.txt"), res.stdout)

    # The spec lists network_eventlog_application.txt; capture Application log similarly.
    app_script = (
        "Get-WinEvent -LogName Application -MaxEvents 300 -ErrorAction SilentlyContinue | "
        "Format-List * | Out-String -Width 4096"
    )
    res2 = run_powershell(app_script, error_log=error_log, timeout=90, label="WinEvent Application")
    _write(os.path.join(folder, "network_eventlog_application.txt"), res2.stdout)


def capture_packets(folder: str, cfg: Config, error_log: CommandErrorLog) -> None:
    """Capture a short, bounded packet trace.

    Preferred: pktmon (-> pktmon_capture.pcapng + pktmon_raw.etl).
    Fallback: netsh trace (-> netsh_trace.etl) if pktmon is unavailable/fails.
    """
    seconds = max(1, int(cfg.packet_capture_seconds))
    etl_path = os.path.join(folder, "PktMon.etl")
    pcap_path = os.path.join(folder, "pktmon_capture.pcapng")
    raw_etl_path = os.path.join(folder, "pktmon_raw.etl")

    pktmon_ok = False
    if cfg.enable_pktmon_capture:
        pktmon_ok = _capture_pktmon(folder, seconds, etl_path, pcap_path, raw_etl_path, error_log)

    if not pktmon_ok and cfg.enable_netsh_trace_fallback:
        _capture_netsh(folder, seconds, error_log)


def _capture_pktmon(
    folder: str,
    seconds: int,
    etl_path: str,
    pcap_path: str,
    raw_etl_path: str,
    error_log: CommandErrorLog,
) -> bool:
    """Run a bounded pktmon capture. Returns True if a pcapng/etl was produced."""
    # Reset any prior filters, add the interesting low-volume protocols, then capture.
    # We run the whole sequence inside a single PowerShell invocation so Start-Sleep
    # bounds the capture window precisely and we always stop even on partial failure.
    script = (
        "pktmon filter remove | Out-Null; "
        "pktmon filter add NetwatchDNS -p 53 | Out-Null; "
        "pktmon filter add NetwatchDHCPs -p 67 | Out-Null; "
        "pktmon filter add NetwatchDHCPc -p 68 | Out-Null; "
        f"pktmon start --capture --pkt-size 0 --comp nics --file-name '{etl_path}' | Out-Null; "
        f"Start-Sleep -Seconds {seconds}; "
        "pktmon stop | Out-Null; "
        f"if(Test-Path '{etl_path}'){{ Copy-Item '{etl_path}' '{raw_etl_path}' -ErrorAction SilentlyContinue }}; "
        f"pktmon etl2pcap '{etl_path}' --out '{pcap_path}' | Out-Null"
    )
    # Total timeout = capture window + generous slack for start/stop/conversion.
    res = run_powershell(
        script, error_log=error_log, timeout=seconds + 60, label="pktmon capture"
    )
    produced = os.path.isfile(pcap_path) or os.path.isfile(raw_etl_path)
    if not produced and res.error:
        error_log.record_raw("pktmon", f"no capture produced: {res.error}")
    return produced


def _capture_netsh(folder: str, seconds: int, error_log: CommandErrorLog) -> None:
    """Fallback packet capture via ``netsh trace`` -> netsh_trace.etl."""
    trace_path = os.path.join(folder, "netsh_trace.etl")
    script = (
        f"netsh trace start capture=yes report=no persistent=no tracefile='{trace_path}' | Out-Null; "
        f"Start-Sleep -Seconds {seconds}; "
        "netsh trace stop | Out-Null"
    )
    run_powershell(script, error_log=error_log, timeout=seconds + 60, label="netsh trace capture")


def write_recent_samples(folder: str, samples: List[Dict[str, Any]]) -> None:
    """Write the recent in-memory samples to recent_samples.jsonl."""
    path = os.path.join(folder, "recent_samples.jsonl")
    try:
        with open(path, "w", encoding="utf-8") as fh:
            for s in samples:
                fh.write(json.dumps(s, ensure_ascii=False) + "\n")
    except OSError:
        pass


def build_summary(
    eid: str,
    classification: str,
    cfg: Config,
    sample: Dict[str, Any],
    history: List[Dict[str, Any]],
    reasons: List[str],
    local_ip_after: Optional[str] = None,
    gateway_mac_after: Optional[str] = None,
) -> Dict[str, Any]:
    """Build the human-readable summary.json dict (spec format)."""
    return {
        "event_id": eid,
        "host_label": cfg.host_label,
        "classification": classification,
        "plain_english": state.plain_english(classification),
        "local_ip_before": sample.get("local_ipv4"),
        "local_ip_after": local_ip_after if local_ip_after is not None else sample.get("local_ipv4"),
        "gateway_ip": sample.get("default_gateway"),
        "gateway_mac_before": sample.get("gateway_mac"),
        "gateway_mac_after": gateway_mac_after if gateway_mac_after is not None else sample.get("gateway_mac"),
        "dns_servers": sample.get("dns_servers", []),
        "internet_ip_ping_ok": sample.get("internet_ping_ok", False),
        "dns_resolution_ok": sample.get("dns_resolution_ok", False),
        "pi_ping_ok": sample.get("pi_ping_ok"),
        "suspicious_findings": state.suspicious_findings(sample, history, reasons),
        "recommended_next_steps": state.recommended_next_steps(classification),
    }


def write_command_errors(folder: str, error_log: CommandErrorLog) -> None:
    path = os.path.join(folder, "command_errors.json")
    try:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(error_log.as_list(), fh, indent=2)
    except OSError:
        pass


def manifest_of(folder: str) -> List[str]:
    """Return the list of files written into the snapshot folder (for event push manifest)."""
    out: List[str] = []
    try:
        for name in sorted(os.listdir(folder)):
            if os.path.isfile(os.path.join(folder, name)):
                out.append(name)
    except OSError:
        pass
    return out


def create_snapshot(
    cfg: Config,
    classification: str,
    sample: Dict[str, Any],
    history: List[Dict[str, Any]],
    reasons: List[str],
    *,
    capture_packets_enabled: bool = True,
    error_log: Optional[CommandErrorLog] = None,
    local_ip_after: Optional[str] = None,
    gateway_mac_after: Optional[str] = None,
) -> str:
    """Create a full event snapshot folder and return its path.

    ``capture_packets_enabled=False`` is used by the ``snapshot`` CLI when a quick capture
    without the (longer) packet trace is desired; by default packet capture runs.
    """
    if error_log is None:
        error_log = CommandErrorLog()

    eid = event_id(classification)
    folder = os.path.join(cfg.events_dir, eid)
    os.makedirs(folder, exist_ok=True)

    # 1. Text diagnostic dumps.
    capture_text_files(folder, error_log)
    # 2. Event logs.
    capture_event_logs(folder, error_log)
    # 3. Recent samples.
    write_recent_samples(folder, history + [sample])
    # 4. Packet capture (bounded).
    if capture_packets_enabled:
        capture_packets(folder, cfg, error_log)
    # 5. Summary + command errors.
    summary = build_summary(
        eid, classification, cfg, sample, history, reasons,
        local_ip_after=local_ip_after, gateway_mac_after=gateway_mac_after,
    )
    try:
        with open(os.path.join(folder, "summary.json"), "w", encoding="utf-8") as fh:
            json.dump(summary, fh, indent=2)
    except OSError:
        pass
    write_command_errors(folder, error_log)

    return folder

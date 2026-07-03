"""Event snapshot capture: writes an event folder with every file in the spec.

On trigger, :func:`create_snapshot` builds:

    /var/log/netwatch-pi/events/YYYY-MM-DD_HH-mm-ss_pi_<classification>/
        summary.json
        recent_samples.jsonl
        ip_addr.txt
        ip_route.txt
        ip_neigh.txt
        arp_an.txt
        resolv_conf.txt
        nmcli_dev_status.txt
        iw_link.txt
        iwconfig.txt
        interface_statistics.json
        journal_network_recent.txt
        journal_system_recent.txt
        tcpdump_capture.pcap
        tcpdump_summary.txt
        command_errors.json

Every external command is wrapped; missing tools/units degrade to a note in the
file and an entry in command_errors.json. Nothing here requires the internet.
"""

from __future__ import annotations

import json
import os
from datetime import datetime
from typing import Dict, List, Optional

from . import classify, pktparse
from .checks import COUNTER_FILES, read_interface_counters
from .shellcmd import CommandErrorCollector, have_tool, run_command

# tcpdump BPF filter from the spec — the interesting "storm/discovery" protocols.
TCPDUMP_FILTER = (
    "(arp or icmp or port 53 or port 67 or port 68 or port 5353 "
    "or port 5355 or port 1900 or broadcast or multicast)"
)


def event_folder_name(classification: str, when: Optional[datetime] = None) -> str:
    """Build ``YYYY-MM-DD_HH-mm-ss_pi_<classification>`` folder basename."""
    when = when or datetime.now()
    return when.strftime("%Y-%m-%d_%H-%M-%S") + f"_pi_{classification}"


def _write_text(path: str, text: str) -> None:
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
    except OSError:
        pass


def _capture_cmd_to_file(
    folder: str, filename: str, args: List[str], collector: CommandErrorCollector
) -> None:
    """Run a command and write its combined output to ``folder/filename``.

    If the tool is missing or the command fails, write an explanatory note and
    record the error — but always produce the file so the folder is complete.
    """
    res = run_command(args, collector=collector)
    if res.ok:
        _write_text(os.path.join(folder, filename), res.stdout)
    else:
        note = (
            f"# command failed or tool unavailable\n"
            f"# command: {res.command}\n"
            f"# error: {res.error}\n"
            f"# stderr:\n{res.stderr}\n"
        )
        _write_text(os.path.join(folder, filename), note)


def _capture_journal(
    folder: str, filename: str, unit: Optional[str], collector: CommandErrorCollector
) -> None:
    """Capture journalctl output (whole system or a specific unit).

    Units may not exist; that is logged but not fatal.
    """
    if not have_tool("journalctl"):
        _write_text(
            os.path.join(folder, filename),
            "# journalctl not available on this system\n",
        )
        return
    args = ["journalctl", "--since", "10 minutes ago", "--no-pager"]
    if unit:
        args = ["journalctl", "-u", unit, "--since", "10 minutes ago", "--no-pager"]
    _capture_cmd_to_file(folder, filename, args, collector)


def _capture_tcpdump(
    folder: str,
    iface: str,
    capture_seconds: int,
    enabled: bool,
    collector: CommandErrorCollector,
) -> None:
    """Run a bounded tcpdump pcap + a short text summary.

    Gracefully no-ops (with a note) if tcpdump is missing, disabled, or we lack
    permission/root. Captures are short and bounded (``capture_seconds``) to keep
    pcap size and SD-card writes small.
    """
    pcap_path = os.path.join(folder, "tcpdump_capture.pcap")
    summary_path = os.path.join(folder, "tcpdump_summary.txt")

    if not enabled:
        _write_text(summary_path, "# tcpdump capture disabled in config\n")
        _write_text(pcap_path, "")
        return
    if not have_tool("tcpdump"):
        _write_text(summary_path, "# tcpdump not installed\n")
        _write_text(pcap_path, "")
        collector.errors.append({"command": "tcpdump", "error": "not installed"})
        return

    # Bounded pcap. Use `timeout` if available so the capture can never hang.
    cap_secs = max(1, int(capture_seconds))
    if have_tool("timeout"):
        pcap_args = [
            "timeout", str(cap_secs),
            "tcpdump", "-i", iface, "-nn", "-e", "-s", "0",
            "-w", pcap_path, TCPDUMP_FILTER,
        ]
    else:
        # No coreutils timeout: bound via -G/-W rotation of a single file window.
        pcap_args = [
            "tcpdump", "-i", iface, "-nn", "-e", "-s", "0",
            "-G", str(cap_secs), "-W", "1",
            "-w", pcap_path, TCPDUMP_FILTER,
        ]
    res = run_command(pcap_args, timeout=cap_secs + 10, collector=collector)
    # Always ensure tcpdump_capture.pcap exists (spec lists it as a required
    # file). If tcpdump could not write it (no permission/not root), create an
    # empty placeholder and record the reason in command_errors.json. Note that
    # `timeout` returning 124 is normal/expected for a successful timed capture.
    if not os.path.exists(pcap_path):
        _write_text(pcap_path, "")
        if not res.ok:
            collector.errors.append(
                {
                    "command": res.command,
                    "error": f"tcpdump pcap not written: {res.error}",
                    "stderr": (res.stderr or "")[:2000],
                }
            )

    # Short text summary (bounded to 300 packets / 15s).
    summary_secs = min(15, cap_secs)
    if have_tool("timeout"):
        sum_args = [
            "timeout", str(summary_secs),
            "tcpdump", "-i", iface, "-nn", "-e", "-c", "300", TCPDUMP_FILTER,
        ]
    else:
        sum_args = [
            "tcpdump", "-i", iface, "-nn", "-e", "-c", "300", TCPDUMP_FILTER,
        ]
    sres = run_command(sum_args, timeout=summary_secs + 10, collector=collector)
    if sres.ok or sres.stdout:
        _write_text(summary_path, sres.stdout or "")
    else:
        _write_text(
            summary_path,
            f"# tcpdump summary failed or empty: {sres.error}\n{sres.stderr}\n",
        )


def create_snapshot(
    cfg,
    classification: str,
    sample: Dict,
    recent_samples: List[Dict],
    prev_gateway_mac: Optional[str] = None,
) -> str:
    """Create a full event-snapshot folder and return its path.

    ``sample`` is the triggering sample; ``recent_samples`` are the latest
    in-memory samples written to recent_samples.jsonl. ``prev_gateway_mac`` is
    the last known-good gateway MAC (for the before/after fields).
    """
    collector = CommandErrorCollector()
    # Seed with any errors already captured while gathering the sample.
    for e in sample.get("_collector_errors", []) or []:
        collector.errors.append(e)

    events_dir = cfg.events_dir
    os.makedirs(events_dir, exist_ok=True)
    folder = os.path.join(events_dir, event_folder_name(classification))
    os.makedirs(folder, exist_ok=True)

    iface = sample.get("interface") or cfg["preferred_interface"] or "wlan0"

    # --- Basic network state ---
    _capture_cmd_to_file(folder, "ip_addr.txt", ["ip", "addr"], collector)
    _capture_cmd_to_file(folder, "ip_route.txt", ["ip", "route"], collector)
    _capture_cmd_to_file(folder, "ip_neigh.txt", ["ip", "neigh"], collector)
    _capture_cmd_to_file(folder, "arp_an.txt", ["arp", "-an"], collector)

    # resolv.conf is a file read, not a command.
    try:
        with open("/etc/resolv.conf", "r", encoding="utf-8") as fh:
            _write_text(os.path.join(folder, "resolv_conf.txt"), fh.read())
    except OSError as exc:
        _write_text(
            os.path.join(folder, "resolv_conf.txt"),
            f"# could not read /etc/resolv.conf: {exc}\n",
        )
        collector.errors.append({"command": "read /etc/resolv.conf", "error": str(exc)})

    # --- Wi-Fi state ---
    _capture_cmd_to_file(folder, "iw_link.txt", ["iw", "dev", iface, "link"], collector)
    _capture_cmd_to_file(folder, "iwconfig.txt", ["iwconfig", iface], collector)
    # nmcli may be entirely absent — write both dev status and dev show.
    if have_tool("nmcli"):
        nm_status = run_command(["nmcli", "dev", "status"], collector=collector)
        nm_show = run_command(["nmcli", "dev", "show", iface], collector=collector)
        combined = (nm_status.stdout or "") + "\n\n" + (nm_show.stdout or "")
        _write_text(os.path.join(folder, "nmcli_dev_status.txt"), combined)
    else:
        _write_text(
            os.path.join(folder, "nmcli_dev_status.txt"),
            "# nmcli not available (system may not use NetworkManager)\n",
        )
        collector.errors.append({"command": "nmcli", "error": "not installed"})

    # --- Interface statistics (JSON) ---
    counters = read_interface_counters(iface, collector)
    _write_text(
        os.path.join(folder, "interface_statistics.json"),
        json.dumps(counters, indent=2),
    )

    # --- Service logs ---
    _capture_journal(folder, "journal_system_recent.txt", None, collector)
    # Network units: try NetworkManager, systemd-networkd, wpa_supplicant; merge.
    net_chunks: List[str] = []
    for unit in ("NetworkManager", "systemd-networkd", "wpa_supplicant"):
        if have_tool("journalctl"):
            res = run_command(
                ["journalctl", "-u", unit, "--since", "10 minutes ago", "--no-pager"],
                collector=collector,
            )
            header = f"===== journalctl -u {unit} =====\n"
            net_chunks.append(header + (res.stdout if res.ok else f"# {res.error}\n"))
        else:
            net_chunks.append("# journalctl not available\n")
            break
    _write_text(os.path.join(folder, "journal_network_recent.txt"), "\n".join(net_chunks))

    # --- Packet capture ---
    _capture_tcpdump(
        folder,
        iface,
        int(cfg["packet_capture_seconds"]),
        bool(cfg["enable_tcpdump_capture"]),
        collector,
    )

    # --- Optional scapy enrichment of the fresh pcap (best-effort) ---
    # Mirrors the Windows side's packet_summary step; parse_pcap returns None
    # (never raises) when scapy is absent or the pcap is empty/corrupt.
    if pktparse.is_available():
        try:
            pkt_summary = pktparse.parse_pcap(
                os.path.join(folder, "tcpdump_capture.pcap")
            )
            if pkt_summary:
                _write_text(
                    os.path.join(folder, "packet_summary.json"),
                    json.dumps(pkt_summary, indent=2),
                )
        except Exception as exc:  # enrichment must never block the snapshot
            collector.errors.append({"command": "pktparse", "error": str(exc)})

    # --- recent_samples.jsonl (strip private keys) ---
    _write_recent_samples(folder, recent_samples)

    # --- summary.json ---
    summary = build_summary(
        cfg, classification, sample, folder, prev_gateway_mac
    )
    _write_text(os.path.join(folder, "summary.json"), json.dumps(summary, indent=2))

    # --- command_errors.json (last, so it includes all capture errors) ---
    _write_text(
        os.path.join(folder, "command_errors.json"),
        json.dumps(collector.as_list(), indent=2),
    )

    return folder


def _strip_private(sample: Dict) -> Dict:
    """Return a copy of a sample without the private underscore-prefixed keys."""
    return {k: v for k, v in sample.items() if not k.startswith("_")}


def _write_recent_samples(folder: str, samples: List[Dict]) -> None:
    try:
        with open(os.path.join(folder, "recent_samples.jsonl"), "w", encoding="utf-8") as fh:
            for s in samples:
                fh.write(json.dumps(_strip_private(s)) + "\n")
    except OSError:
        pass


def build_summary(
    cfg,
    classification: str,
    sample: Dict,
    folder: str,
    prev_gateway_mac: Optional[str],
) -> Dict:
    """Build the human-readable summary.json dict (exact format from the spec)."""
    current_mac = sample.get("gateway_mac")
    mac_changed = bool(
        prev_gateway_mac and current_mac and prev_gateway_mac != current_mac
    )
    return {
        "event_id": os.path.basename(folder),
        "host_label": cfg["host_label"],
        "classification": classification,
        "plain_english": classify.plain_english(classification, sample),
        "local_ip": sample.get("local_ipv4"),
        "gateway_ip": sample.get("default_gateway"),
        "gateway_mac_before": prev_gateway_mac,
        "gateway_mac_after": current_mac,
        "windows_desktop_ip": cfg["windows_desktop_ip"],
        "gateway_ping_ok": sample.get("gateway_ping_ok"),
        "internet_ip_ping_ok": sample.get("internet_ping_ok"),
        "dns_resolution_ok": sample.get("dns_resolution_ok"),
        "windows_ping_ok": sample.get("windows_ping_ok"),
        "wifi_signal_dbm": sample.get("wifi_signal_dbm"),
        "suspicious_findings": classify.suspicious_findings(
            classification, sample, mac_changed
        ),
        "recommended_next_steps": classify.recommended_next_steps(classification),
    }

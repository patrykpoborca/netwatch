"""The 8 health checks plus helpers, all using Linux shell commands.

Each function is defensive: any missing tool / failure returns a "negative but
non-crashing" result and records the error into the provided collector. The
output of :func:`gather_sample` is one JSONL health sample exactly matching the
schema in the spec (classification is filled in later by the state machine).
"""

from __future__ import annotations

import os
import re
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from .shellcmd import CommandErrorCollector, have_tool, run_command


# --------------------------------------------------------------------------- #
# Timestamp helper
# --------------------------------------------------------------------------- #
def now_timestamp() -> str:
    """Local time with timezone offset, e.g. 2026-06-07T22:41:03.123-05:00.

    Uses the local timezone so the Pi's timestamps line up with the Windows
    desktop's event folders (per the runbook's time-sync requirement).
    """
    local_tz = datetime.now(timezone.utc).astimezone().tzinfo
    dt = datetime.now(local_tz)
    # Millisecond precision, keep the colon-less offset Python emits then insert.
    base = dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}"
    offset = dt.strftime("%z")  # like -0500
    if offset:
        offset = offset[:3] + ":" + offset[3:]
    return base + offset


# --------------------------------------------------------------------------- #
# 1. Interface detection
# --------------------------------------------------------------------------- #
def detect_default_route_interface(
    collector: CommandErrorCollector,
) -> Tuple[Optional[str], Optional[str]]:
    """Return (interface, gateway_ip) from ``ip route show default``.

    Example line: ``default via 192.168.4.1 dev wlan0 proto dhcp metric 600``
    """
    res = run_command(["ip", "route", "show", "default"], collector=collector)
    if not res.ok or not res.stdout.strip():
        return None, None
    line = res.stdout.strip().splitlines()[0]
    gw_match = re.search(r"via\s+(\d+\.\d+\.\d+\.\d+)", line)
    dev_match = re.search(r"dev\s+(\S+)", line)
    gw = gw_match.group(1) if gw_match else None
    dev = dev_match.group(1) if dev_match else None
    return dev, gw


def interface_exists(iface: str) -> bool:
    """True if /sys/class/net/<iface> exists (no external tool needed)."""
    return bool(iface) and os.path.isdir(f"/sys/class/net/{iface}")


def resolve_interface(
    preferred: Optional[str], collector: CommandErrorCollector
) -> Tuple[Optional[str], Optional[str]]:
    """Pick the interface to monitor.

    Prefer the configured interface if it exists; otherwise fall back to the
    default-route interface. Also returns the detected default gateway (may be
    None) so callers can reuse it.
    """
    detected_iface, detected_gw = detect_default_route_interface(collector)
    if preferred and interface_exists(preferred):
        return preferred, detected_gw
    if detected_iface and interface_exists(detected_iface):
        return detected_iface, detected_gw
    # Last resort: return preferred (even if absent) so downstream logs are clear.
    return preferred or detected_iface, detected_gw


def get_local_ipv4(iface: str, collector: CommandErrorCollector) -> Optional[str]:
    """Return the first non-loopback IPv4 on ``iface`` via ``ip addr show``."""
    res = run_command(["ip", "-4", "addr", "show", "dev", iface], collector=collector)
    if not res.ok:
        return None
    m = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)", res.stdout)
    return m.group(1) if m else None


# --------------------------------------------------------------------------- #
# 2. Wi-Fi association
# --------------------------------------------------------------------------- #
def get_wifi_status(
    iface: str, collector: CommandErrorCollector
) -> Dict[str, object]:
    """Return Wi-Fi association info using ``iw`` (preferred) or ``iwconfig``.

    Keys: wifi_associated (bool), wifi_ssid, wifi_bssid, wifi_signal_dbm,
    wifi_tx_bitrate. Wired/unknown interfaces simply return associated=False
    with the rest None — callers treat that as "not a Wi-Fi disconnect" only
    when there is otherwise a valid IP/route (handled in the state machine).
    """
    info: Dict[str, object] = {
        "wifi_associated": False,
        "wifi_ssid": None,
        "wifi_bssid": None,
        "wifi_signal_dbm": None,
        "wifi_tx_bitrate": None,
    }

    # Preferred: iw dev <iface> link
    if have_tool("iw"):
        res = run_command(["iw", "dev", iface, "link"], collector=collector)
        if res.ok and "Not connected" not in res.stdout:
            text = res.stdout
            if "Connected to" in text:
                info["wifi_associated"] = True
            bssid = re.search(r"Connected to\s+([0-9a-fA-F:]{17})", text)
            if bssid:
                info["wifi_bssid"] = bssid.group(1)
            ssid = re.search(r"SSID:\s+(.+)", text)
            if ssid:
                info["wifi_ssid"] = ssid.group(1).strip()
            signal = re.search(r"signal:\s+(-?\d+)\s*dBm", text)
            if signal:
                info["wifi_signal_dbm"] = int(signal.group(1))
            bitrate = re.search(r"tx bitrate:\s+([\d.]+)\s*MBit/s", text)
            if bitrate:
                info["wifi_tx_bitrate"] = float(bitrate.group(1))
            if info["wifi_associated"]:
                return info

    # Fallback: iwconfig <iface>
    if have_tool("iwconfig"):
        res = run_command(["iwconfig", iface], collector=collector)
        if res.ok:
            text = res.stdout
            ssid = re.search(r'ESSID:"([^"]*)"', text)
            if ssid and ssid.group(1) and ssid.group(1).lower() != "off/any":
                info["wifi_ssid"] = ssid.group(1)
                info["wifi_associated"] = True
            ap = re.search(r"Access Point:\s+([0-9A-Fa-f:]{17})", text)
            if ap:
                info["wifi_bssid"] = ap.group(1)
                info["wifi_associated"] = True
            signal = re.search(r"Signal level[=:]\s*(-?\d+)\s*dBm", text)
            if signal:
                info["wifi_signal_dbm"] = int(signal.group(1))
            bitrate = re.search(r"Bit Rate[=:]\s*([\d.]+)\s*Mb/s", text)
            if bitrate:
                info["wifi_tx_bitrate"] = float(bitrate.group(1))

    return info


# --------------------------------------------------------------------------- #
# 3 + 4 + 6. Ping helpers
# --------------------------------------------------------------------------- #
def ping(ip: str, collector: CommandErrorCollector, count: int = 2, wait: int = 2) -> bool:
    """Return True if ``ping -c <count> -W <wait> <ip>`` succeeds."""
    if not ip:
        return False
    res = run_command(
        ["ping", "-c", str(count), "-W", str(wait), ip],
        collector=collector,
        timeout=count * wait + 5,
    )
    return res.ok


def ping_any(ips: List[str], collector: CommandErrorCollector) -> bool:
    """Return True if ANY of the given IPs is pingable (used for internet check)."""
    for ip in ips:
        if ping(ip, collector):
            return True
    return False


# --------------------------------------------------------------------------- #
# 5. DNS resolution
# --------------------------------------------------------------------------- #
def dns_resolves(name: str, collector: CommandErrorCollector) -> bool:
    """Resolve ``name`` via ``dig`` (preferred), fall back to ``getent hosts``."""
    if have_tool("dig"):
        res = run_command(
            ["dig", "+time=2", "+tries=1", "+short", name], collector=collector
        )
        if res.ok and res.stdout.strip():
            # Any A/AAAA answer line means success.
            for line in res.stdout.strip().splitlines():
                if re.match(r"^[\d.]+$|^[0-9a-fA-F:]+$", line.strip()):
                    return True
        # dig ran but no answer — fall through to getent as a second opinion.
    if have_tool("getent"):
        res = run_command(["getent", "hosts", name], collector=collector)
        if res.ok and res.stdout.strip():
            return True
    return False


def dns_resolution_ok(names: List[str], collector: CommandErrorCollector) -> bool:
    """True if at least one configured DNS name resolves."""
    for name in names:
        if dns_resolves(name, collector):
            return True
    return False


def get_dns_servers(collector: CommandErrorCollector) -> List[str]:
    """Parse nameservers from /etc/resolv.conf (no external tool)."""
    servers: List[str] = []
    try:
        with open("/etc/resolv.conf", "r", encoding="utf-8") as fh:
            for line in fh:
                m = re.match(r"\s*nameserver\s+(\S+)", line)
                if m:
                    servers.append(m.group(1))
    except OSError as exc:
        collector.errors.append(
            {"command": "read /etc/resolv.conf", "error": str(exc)}
        )
    return servers


# --------------------------------------------------------------------------- #
# 7. Gateway ARP / neighbor
# --------------------------------------------------------------------------- #
def get_gateway_mac(
    gateway_ip: Optional[str], collector: CommandErrorCollector
) -> Optional[str]:
    """Return the gateway's MAC from ``ip neigh show <gw>``."""
    if not gateway_ip:
        return None
    res = run_command(["ip", "neigh", "show", gateway_ip], collector=collector)
    if not res.ok:
        return None
    m = re.search(r"lladdr\s+([0-9a-fA-F:]{17})", res.stdout)
    return m.group(1).lower() if m else None


# --------------------------------------------------------------------------- #
# 8. Interface counters
# --------------------------------------------------------------------------- #
COUNTER_FILES = [
    "rx_bytes",
    "tx_bytes",
    "rx_packets",
    "tx_packets",
    "rx_errors",
    "tx_errors",
    "rx_dropped",
    "tx_dropped",
]


def read_interface_counters(
    iface: str, collector: CommandErrorCollector
) -> Dict[str, Optional[int]]:
    """Read all counters under /sys/class/net/<iface>/statistics/.

    Direct file reads (no external command) — cheap and always available.
    """
    counters: Dict[str, Optional[int]] = {}
    base = f"/sys/class/net/{iface}/statistics"
    for name in COUNTER_FILES:
        path = os.path.join(base, name)
        try:
            with open(path, "r", encoding="utf-8") as fh:
                counters[name] = int(fh.read().strip())
        except (OSError, ValueError) as exc:
            counters[name] = None
            collector.errors.append({"command": f"read {path}", "error": str(exc)})
    return counters


# --------------------------------------------------------------------------- #
# Sample assembly
# --------------------------------------------------------------------------- #
def gather_sample(cfg, prev_counters: Optional[Dict[str, Optional[int]]] = None) -> Dict:
    """Run all 8 checks and assemble one health sample dict.

    ``classification`` is set to a placeholder here; the state machine computes
    the authoritative classification. The returned dict also carries a private
    ``_collector`` and ``_wifi`` we strip before writing (used by the loop).
    """
    collector = CommandErrorCollector()
    targets = cfg.targets

    # 1. Interface + gateway
    iface, detected_gw = resolve_interface(cfg["preferred_interface"], collector)
    iface = iface or cfg["preferred_interface"] or "wlan0"
    gateway = cfg["gateway_ip_override"] or detected_gw

    local_ipv4 = get_local_ipv4(iface, collector) if interface_exists(iface) else None

    # 2. Wi-Fi
    wifi = get_wifi_status(iface, collector)

    # 3. Gateway ping
    gateway_ping_ok = ping(gateway, collector) if gateway else False

    # 4. Internet ping (any)
    internet_ping_ok = ping_any(list(targets.get("internet_ips", [])), collector)

    # 5. DNS
    dns_ok = dns_resolution_ok(list(targets.get("dns_names", [])), collector)
    dns_servers = get_dns_servers(collector)

    # 6. Windows desktop cross-ping (skip if not configured)
    win_ip = cfg["windows_desktop_ip"]
    if win_ip:
        windows_ping_ok = ping(win_ip, collector)
    else:
        windows_ping_ok = None

    # 7. Gateway MAC
    gateway_mac = get_gateway_mac(gateway, collector)

    # 8. Counters
    counters = read_interface_counters(iface, collector)

    sample = {
        "timestamp": now_timestamp(),
        "host_label": cfg["host_label"],
        "os": "Linux",
        "interface": iface,
        "local_ipv4": local_ipv4,
        "default_gateway": gateway,
        "dns_servers": dns_servers,
        "wifi_associated": bool(wifi["wifi_associated"]),
        "wifi_ssid": wifi["wifi_ssid"],
        "wifi_signal_dbm": wifi["wifi_signal_dbm"],
        "gateway_ping_ok": gateway_ping_ok,
        "internet_ping_ok": internet_ping_ok,
        "dns_resolution_ok": dns_ok,
        "windows_ping_ok": windows_ping_ok,
        "gateway_mac": gateway_mac,
        "rx_bytes": counters.get("rx_bytes"),
        "tx_bytes": counters.get("tx_bytes"),
        "rx_errors": counters.get("rx_errors"),
        "tx_errors": counters.get("tx_errors"),
        "classification": "healthy",  # provisional; state machine overrides
    }

    # Private extras (not part of the JSONL schema; stripped before writing).
    sample["_collector_errors"] = collector.as_list()
    sample["_counters_full"] = counters
    sample["_wifi"] = wifi
    return sample

"""The seven per-cycle health checks plus adapter detection.

Each function is defensive: a missing command or unexpected output yields a "negative"
/ unknown result rather than an exception, and any failure is recorded into the shared
:class:`~netwatch.runner.CommandErrorLog`.

PowerShell is the primary source of truth (it returns clean values via ``ConvertTo-Json``
or simple ``Write-Output`` markers). Where the spec calls for cmd tools (``arp``,
``ipconfig``) we use them and parse text.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .runner import CommandErrorLog, run_cmd, run_powershell


# Substrings (case-insensitive) that mark an adapter as "suspicious" per the spec.
SUSPICIOUS_ADAPTER_PATTERNS: List[str] = [
    "hyper-v",
    "vethernet",
    "docker",
    "wsl",
    "vpn",
    "tap",
    "tun",
    "bridge",
    "internet connection sharing",
    "ics",
    "virtual",
    "vmware",
    "virtualbox",
    "tailscale",
    "wireguard",
    "zerotier",
    "openvpn",
    "nordvpn",
    "expressvpn",
]


@dataclass
class AdapterInfo:
    name: str
    interface_description: str
    status: str
    link_speed: str
    mac_address: str
    is_suspicious: bool
    suspicious_reasons: List[str] = field(default_factory=list)


def _ps_json(result_stdout: str) -> Any:
    """Parse PowerShell ``ConvertTo-Json`` output, tolerating empty / single-object output."""
    text = (result_stdout or "").strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        return None


def _classify_suspicious(name: str, description: str) -> List[str]:
    """Return the list of patterns that mark this adapter suspicious (empty if clean)."""
    haystack = f"{name} {description}".lower()
    reasons: List[str] = []
    for pat in SUSPICIOUS_ADAPTER_PATTERNS:
        if pat in haystack:
            reasons.append(pat)
    return reasons


# ---------------------------------------------------------------------------
# Check 1: adapter detection (incl. suspicious virtual/bridge/VPN adapters)
# ---------------------------------------------------------------------------

def detect_adapters(error_log: CommandErrorLog) -> List[AdapterInfo]:
    """Enumerate all net adapters and flag suspicious virtual/bridge/VPN ones.

    Uses ``Get-NetAdapter`` (all adapters, not just Up, so virtual/bridge adapters that
    are administratively up still surface).
    """
    script = (
        "Get-NetAdapter | "
        "Select-Object Name, InterfaceDescription, Status, "
        "@{N='LinkSpeed';E={[string]$_.LinkSpeed}}, MacAddress | ConvertTo-Json -Depth 3"
    )
    res = run_powershell(script, error_log=error_log, label="Get-NetAdapter(detect)")
    data = _ps_json(res.stdout)
    adapters: List[AdapterInfo] = []
    if data is None:
        return adapters
    if isinstance(data, dict):
        data = [data]
    for item in data:
        name = str(item.get("Name", "") or "")
        desc = str(item.get("InterfaceDescription", "") or "")
        reasons = _classify_suspicious(name, desc)
        adapters.append(
            AdapterInfo(
                name=name,
                interface_description=desc,
                status=str(item.get("Status", "") or ""),
                link_speed=str(item.get("LinkSpeed", "") or ""),
                mac_address=str(item.get("MacAddress", "") or ""),
                is_suspicious=bool(reasons),
                suspicious_reasons=reasons,
            )
        )
    return adapters


def choose_active_adapter(
    adapters: List[AdapterInfo], preferred_alias: Optional[str]
) -> Optional[AdapterInfo]:
    """Pick the working adapter: preferred alias if Up, else first non-suspicious Up adapter."""
    up = [a for a in adapters if a.status.lower() == "up"]
    if preferred_alias:
        for a in up:
            if a.name.lower() == preferred_alias.lower():
                return a
    # Prefer a non-suspicious physical adapter.
    for a in up:
        if not a.is_suspicious:
            return a
    return up[0] if up else None


# ---------------------------------------------------------------------------
# Check 2: link state + statistics
# ---------------------------------------------------------------------------

def get_ip_configuration(alias: Optional[str], error_log: CommandErrorLog) -> Dict[str, Any]:
    """Return local IPv4, default gateway, and DNS servers for the chosen adapter.

    Falls back to a global ``Get-NetIPConfiguration`` if no alias resolves.
    """
    if alias:
        script = (
            f"$c = Get-NetIPConfiguration -InterfaceAlias '{alias}' -ErrorAction SilentlyContinue; "
            "if(-not $c){ $c = Get-NetIPConfiguration | Where-Object {$_.IPv4Address} | Select-Object -First 1 }; "
            "[pscustomobject]@{ "
            "IPv4 = ($c.IPv4Address.IPAddress | Select-Object -First 1); "
            "Gateway = ($c.IPv4DefaultGateway.NextHop | Select-Object -First 1); "
            "DNS = @($c.DNSServer | Where-Object {$_.AddressFamily -eq 2} | "
            "ForEach-Object {$_.ServerAddresses}) "
            "} | ConvertTo-Json -Depth 4"
        )
    else:
        script = (
            "$c = Get-NetIPConfiguration | Where-Object {$_.IPv4Address} | Select-Object -First 1; "
            "[pscustomobject]@{ "
            "IPv4 = ($c.IPv4Address.IPAddress | Select-Object -First 1); "
            "Gateway = ($c.IPv4DefaultGateway.NextHop | Select-Object -First 1); "
            "DNS = @($c.DNSServer | Where-Object {$_.AddressFamily -eq 2} | "
            "ForEach-Object {$_.ServerAddresses}) "
            "} | ConvertTo-Json -Depth 4"
        )
    res = run_powershell(script, error_log=error_log, label="Get-NetIPConfiguration")
    data = _ps_json(res.stdout) or {}
    dns = data.get("DNS")
    if dns is None:
        dns_list: List[str] = []
    elif isinstance(dns, list):
        dns_list = [str(d) for d in dns if d]
    else:
        dns_list = [str(dns)]
    return {
        "local_ipv4": data.get("IPv4"),
        "default_gateway": data.get("Gateway"),
        "dns_servers": dns_list,
    }


def get_link_state(alias: Optional[str], error_log: CommandErrorLog) -> Dict[str, Any]:
    """Return link up/down, speed, description and MAC for ``alias``."""
    if not alias:
        return {
            "link_up": False,
            "link_speed": None,
            "interface_description": None,
            "mac_address": None,
        }
    script = (
        f"$a = Get-NetAdapter -Name '{alias}' -ErrorAction SilentlyContinue; "
        "if($a){ [pscustomobject]@{ "
        "Up = ($a.Status -eq 'Up'); "
        "LinkSpeed = [string]$a.LinkSpeed; "
        "Description = $a.InterfaceDescription; "
        "Mac = $a.MacAddress "
        "} | ConvertTo-Json }"
    )
    res = run_powershell(script, error_log=error_log, label=f"Get-NetAdapter({alias})")
    data = _ps_json(res.stdout) or {}
    return {
        "link_up": bool(data.get("Up", False)),
        "link_speed": data.get("LinkSpeed"),
        "interface_description": data.get("Description"),
        "mac_address": data.get("Mac"),
    }


def get_adapter_statistics(alias: Optional[str], error_log: CommandErrorLog) -> Dict[str, Any]:
    """Return rx/tx byte and error/discard counters for ``alias`` (0/None on failure)."""
    blank = {
        "adapter_rx_bytes": 0,
        "adapter_tx_bytes": 0,
        "adapter_rx_errors": 0,
        "adapter_tx_errors": 0,
        "adapter_rx_discards": 0,
        "adapter_tx_discards": 0,
    }
    if not alias:
        return blank
    script = (
        f"$s = Get-NetAdapterStatistics -Name '{alias}' -ErrorAction SilentlyContinue; "
        "if($s){ [pscustomobject]@{ "
        "Rx = [int64]$s.ReceivedBytes; "
        "Tx = [int64]$s.SentBytes; "
        "RxErr = [int64]$s.ReceivedPacketErrors; "
        "TxErr = [int64]$s.OutboundPacketErrors; "
        "RxDisc = [int64]$s.ReceivedDiscardedPackets; "
        "TxDisc = [int64]$s.OutboundDiscardedPackets "
        "} | ConvertTo-Json }"
    )
    res = run_powershell(script, error_log=error_log, label=f"Get-NetAdapterStatistics({alias})")
    data = _ps_json(res.stdout)
    if not data:
        return blank
    return {
        "adapter_rx_bytes": int(data.get("Rx", 0) or 0),
        "adapter_tx_bytes": int(data.get("Tx", 0) or 0),
        "adapter_rx_errors": int(data.get("RxErr", 0) or 0),
        "adapter_tx_errors": int(data.get("TxErr", 0) or 0),
        "adapter_rx_discards": int(data.get("RxDisc", 0) or 0),
        "adapter_tx_discards": int(data.get("TxDisc", 0) or 0),
    }


# ---------------------------------------------------------------------------
# Checks 3, 4, 6: ping helpers
# ---------------------------------------------------------------------------

def ping_ok(target: str, error_log: CommandErrorLog, count: int = 2, timeout: float = 12.0) -> bool:
    """Return True if ``target`` answers. Uses ``Test-Connection ... -Quiet`` per the spec."""
    if not target:
        return False
    script = (
        f"if(Test-Connection -ComputerName '{target}' -Count {count} -Quiet "
        "-ErrorAction SilentlyContinue){'TRUE'}else{'FALSE'}"
    )
    res = run_powershell(script, error_log=error_log, timeout=timeout, label=f"ping {target}")
    return "TRUE" in (res.stdout or "").upper()


def gateway_ping(gateway: Optional[str], error_log: CommandErrorLog) -> bool:
    """Check 3: ping the default gateway."""
    if not gateway:
        return False
    return ping_ok(gateway, error_log)


def internet_ping(ips: List[str], error_log: CommandErrorLog) -> bool:
    """Check 4: True if ANY configured public IP answers (spec: 'both public IP pings fail')."""
    for ip in ips:
        if ping_ok(ip, error_log):
            return True
    return False


def pi_ping(pi_ip: Optional[str], error_log: CommandErrorLog) -> Optional[bool]:
    """Check 6: cross-ping the Raspberry Pi. Returns None when no Pi is configured."""
    if not pi_ip:
        return None
    return ping_ok(pi_ip, error_log)


# ---------------------------------------------------------------------------
# Check 5: DNS resolution
# ---------------------------------------------------------------------------

def dns_resolution_ok(names: List[str], error_log: CommandErrorLog) -> bool:
    """Check 5: True if ANY configured name resolves to an address."""
    if not names:
        return True  # nothing to resolve -> not a DNS failure
    for name in names:
        script = (
            f"$r = Resolve-DnsName '{name}' -ErrorAction SilentlyContinue; "
            "if($r){'TRUE'}else{'FALSE'}"
        )
        res = run_powershell(script, error_log=error_log, timeout=12.0, label=f"Resolve-DnsName {name}")
        if "TRUE" in (res.stdout or "").upper():
            return True
    return False


# ---------------------------------------------------------------------------
# Check 7: gateway ARP / neighbor entry
# ---------------------------------------------------------------------------

def gateway_mac(gateway: Optional[str], error_log: CommandErrorLog) -> Optional[str]:
    """Check 7: resolve the gateway's MAC via Get-NetNeighbor, falling back to ``arp -a``."""
    if not gateway:
        return None
    script = (
        f"$n = Get-NetNeighbor -IPAddress '{gateway}' -ErrorAction SilentlyContinue | "
        "Where-Object {$_.LinkLayerAddress -and $_.LinkLayerAddress -ne '00-00-00-00-00-00'} | "
        "Select-Object -First 1; if($n){$n.LinkLayerAddress}"
    )
    res = run_powershell(script, error_log=error_log, label=f"Get-NetNeighbor({gateway})")
    mac = (res.stdout or "").strip()
    if mac:
        return _normalize_mac(mac)

    # Fallback: parse `arp -a`.
    arp = run_cmd(["arp", "-a"], error_log=error_log, label="arp -a")
    return _parse_arp_mac(arp.stdout, gateway)


def _normalize_mac(mac: str) -> str:
    """Normalize MAC to lowercase hyphen-separated form (aa-bb-cc-dd-ee-ff)."""
    cleaned = mac.strip().lower().replace(":", "-")
    return cleaned


def _parse_arp_mac(arp_output: str, gateway: str) -> Optional[str]:
    """Extract the MAC for ``gateway`` from ``arp -a`` text output."""
    for line in (arp_output or "").splitlines():
        if gateway in line:
            # Format: "  192.168.4.1     aa-bb-cc-dd-ee-ff     dynamic"
            m = re.search(r"([0-9a-fA-F]{2}(?:[-:][0-9a-fA-F]{2}){5})", line)
            if m:
                return _normalize_mac(m.group(1))
    return None

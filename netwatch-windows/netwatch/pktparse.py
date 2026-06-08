"""Optional packet-capture parsing (Scapy / PyShark).

This module is entirely optional. Imports are guarded so the app works fully without
either library installed (v1 does NOT require packet parsing). When a parser is available
and a ``.pcapng`` exists, :func:`summarize_capture` produces a small text summary of
storm-relevant counts (broadcast/multicast/ARP/DHCP/DNS/mDNS/SSDP/LLMNR/NetBIOS and top
MAC addresses).
"""

from __future__ import annotations

import os
from collections import Counter
from typing import Dict, List, Optional

# Guarded optional imports -- never required.
try:  # pragma: no cover - environment dependent
    from scapy.all import rdpcap  # type: ignore
    _HAVE_SCAPY = True
except Exception:  # noqa: BLE001
    _HAVE_SCAPY = False

try:  # pragma: no cover - environment dependent
    import pyshark  # type: ignore  # noqa: F401
    _HAVE_PYSHARK = True
except Exception:  # noqa: BLE001
    _HAVE_PYSHARK = False


def available() -> bool:
    """True if any optional packet parser is importable."""
    return _HAVE_SCAPY or _HAVE_PYSHARK


def summarize_capture(pcap_path: str, max_packets: int = 50000) -> Optional[str]:
    """Return a small text summary of the capture, or None if parsing is unavailable.

    Best-effort: any parsing error returns a short note rather than raising.
    """
    if not os.path.isfile(pcap_path):
        return None
    if _HAVE_SCAPY:
        return _summarize_scapy(pcap_path, max_packets)
    return None


def _summarize_scapy(pcap_path: str, max_packets: int) -> str:
    try:
        packets = rdpcap(pcap_path)  # type: ignore[name-defined]
    except Exception as exc:  # noqa: BLE001
        return f"[netwatch] scapy failed to parse {pcap_path}: {exc}\n"

    src_macs: Counter = Counter()
    dst_macs: Counter = Counter()
    counts = {
        "total": 0,
        "broadcast": 0,
        "multicast": 0,
        "arp": 0,
        "dhcp": 0,
        "dns": 0,
        "mdns": 0,
        "ssdp": 0,
        "llmnr": 0,
        "netbios": 0,
    }

    for i, pkt in enumerate(packets):
        if i >= max_packets:
            break
        counts["total"] += 1
        try:
            if pkt.haslayer("Ether"):
                eth = pkt["Ether"]
                src_macs[eth.src] += 1
                dst_macs[eth.dst] += 1
                if eth.dst.lower() == "ff:ff:ff:ff:ff:ff":
                    counts["broadcast"] += 1
                elif int(eth.dst.split(":")[0], 16) & 1:  # multicast LSB of first octet
                    counts["multicast"] += 1
            if pkt.haslayer("ARP"):
                counts["arp"] += 1
            if pkt.haslayer("UDP"):
                udp = pkt["UDP"]
                sp, dp = int(udp.sport), int(udp.dport)
                if dp in (67, 68) or sp in (67, 68):
                    counts["dhcp"] += 1
                if dp == 53 or sp == 53:
                    counts["dns"] += 1
                if dp == 5353 or sp == 5353:
                    counts["mdns"] += 1
                if dp == 1900 or sp == 1900:
                    counts["ssdp"] += 1
                if dp == 5355 or sp == 5355:
                    counts["llmnr"] += 1
                if dp == 137 or sp == 137:
                    counts["netbios"] += 1
        except Exception:  # noqa: BLE001 - per-packet robustness
            continue

    lines: List[str] = ["# Packet capture summary (scapy)", ""]
    for k, v in counts.items():
        lines.append(f"{k}: {v}")
    lines.append("")
    lines.append("# Top source MACs")
    for mac, c in src_macs.most_common(10):
        lines.append(f"{mac}: {c}")
    lines.append("")
    lines.append("# Top destination MACs")
    for mac, c in dst_macs.most_common(10):
        lines.append(f"{mac}: {c}")
    lines.append("")
    return "\n".join(lines)

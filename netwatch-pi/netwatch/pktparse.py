"""Optional packet-capture parsing (NOT required for v1).

If an optional packet-parsing library (scapy) is available, summarize a pcap for
storm/discovery indicators. The import is wrapped in try/except so the app works
perfectly without it. This is invoked only as a best-effort enrichment and never
blocks snapshot creation.
"""

from __future__ import annotations

import collections
from typing import Dict, Optional

# Optional dependency — absence is fine (v1 does not require packet parsing).
try:  # pragma: no cover - depends on environment
    from scapy.all import rdpcap  # type: ignore
    from scapy.layers.l2 import ARP, Ether  # type: ignore
    from scapy.layers.inet import IP, UDP  # type: ignore

    _SCAPY_AVAILABLE = True
except Exception:  # broad: any import error means "not available"
    _SCAPY_AVAILABLE = False


def is_available() -> bool:
    """True if optional packet parsing can run."""
    return _SCAPY_AVAILABLE


def parse_pcap(
    path: str, windows_mac: Optional[str] = None, max_packets: int = 50000
) -> Optional[Dict]:
    """Parse ``path`` and return a summary dict, or None if unavailable/failed.

    The summary counts total/broadcast/multicast/ARP/DHCP/DNS/mDNS/SSDP frames
    and lists top source MACs / source + destination IPs, plus whether a MAC
    matching the Windows desktop appeared repeatedly.

    ``max_packets`` bounds the per-packet loop (mirroring the Windows side's
    cap) so a storm-sized capture cannot pin the CPU during snapshot creation.
    A truncated/corrupt pcap (including the empty placeholder file written
    when tcpdump cannot run) makes ``rdpcap`` raise, which returns None.
    """
    if not _SCAPY_AVAILABLE:
        return None
    try:
        packets = rdpcap(path)
    except Exception:
        return None

    summary = {
        "total_packets": 0,
        "broadcast_frames": 0,
        "multicast_frames": 0,
        "arp_count": 0,
        "dhcp_count": 0,
        "dns_count": 0,
        "mdns_count": 0,
        "ssdp_count": 0,
        "top_src_macs": [],
        "top_src_ips": [],
        "top_dst_ips": [],
        "windows_mac_repeats": 0,
    }
    src_macs = collections.Counter()
    src_ips = collections.Counter()
    dst_ips = collections.Counter()
    win_mac = (windows_mac or "").lower() or None

    for i, pkt in enumerate(packets):
        if i >= max_packets:
            summary["truncated_at"] = max_packets
            break
        summary["total_packets"] += 1
        try:
            if Ether in pkt:
                dst = pkt[Ether].dst.lower()
                src = pkt[Ether].src.lower()
                src_macs[src] += 1
                if dst == "ff:ff:ff:ff:ff:ff":
                    summary["broadcast_frames"] += 1
                elif int(dst.split(":")[0], 16) & 1:  # multicast bit
                    summary["multicast_frames"] += 1
                if win_mac and src == win_mac:
                    summary["windows_mac_repeats"] += 1
            if ARP in pkt:
                summary["arp_count"] += 1
            if IP in pkt:
                src_ips[pkt[IP].src] += 1
                dst_ips[pkt[IP].dst] += 1
            if UDP in pkt:
                sport = pkt[UDP].sport
                dport = pkt[UDP].dport
                ports = {sport, dport}
                if ports & {67, 68}:
                    summary["dhcp_count"] += 1
                if 53 in ports:
                    summary["dns_count"] += 1
                if 5353 in ports:
                    summary["mdns_count"] += 1
                if 1900 in ports:
                    summary["ssdp_count"] += 1
        except Exception:
            # Skip malformed frames rather than abort the whole parse.
            continue

    summary["top_src_macs"] = src_macs.most_common(10)
    summary["top_src_ips"] = src_ips.most_common(10)
    summary["top_dst_ips"] = dst_ips.most_common(10)
    return summary

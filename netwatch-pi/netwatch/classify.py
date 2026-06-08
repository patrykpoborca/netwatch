"""Event classification + degraded-sample detection + plain-English summaries.

This implements the spec's classification logic exactly and the runbook's
paired Windows+Pi interpretation in the plain-English summary text.

Classification priority (most fundamental failure first):

    wifi_disconnected      -> wlan interface not associated
    no_ipv4                -> associated but no IPv4
    gateway_unreachable    -> have IPv4 but gateway ping fails
    wan_unreachable        -> gateway ok but both public IP pings fail
    dns_only_failure       -> gateway+public ok but DNS fails
    possible_arp_conflict  -> gateway MAC changed / duplicate gateway
    windows_unreachable_from_pi -> Pi healthy but Windows ping failed (low severity)
    possible_broadcast_storm    -> counter/tcpdump heuristics (rare; see notes)
    healthy                -> all checks pass
"""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

# Counter-based heuristic threshold for a "sharp" error/drop increase between
# consecutive polls. Conservative so we do not over-flag normal jitter.
SHARP_ERROR_DELTA = 100


def is_wired_interface(sample: Dict) -> bool:
    """Heuristic: treat an interface with no Wi-Fi SSID/BSSID and a name like
    eth*/en* as wired, so we don't mislabel a wired Pi as 'wifi_disconnected'.
    """
    iface = (sample.get("interface") or "").lower()
    if sample.get("wifi_ssid") or sample.get("_wifi", {}).get("wifi_bssid"):
        return False
    return iface.startswith("eth") or iface.startswith("en")


def classify_sample(
    sample: Dict,
    prev_sample: Optional[Dict] = None,
    expected_gateway_mac: Optional[str] = None,
) -> str:
    """Return the spec classification string for a single sample.

    ``prev_sample`` is used for delta-based heuristics (counter spikes, Windows
    ping OK->failed transition). ``expected_gateway_mac`` is the last known-good
    gateway MAC used to detect ARP conflicts.
    """
    wired = is_wired_interface(sample)

    # wifi_disconnected — only meaningful for Wi-Fi interfaces.
    if not wired and not sample.get("wifi_associated"):
        return "wifi_disconnected"

    # no_ipv4 — associated (or wired+up) but no address.
    if not sample.get("local_ipv4"):
        return "no_ipv4"

    # gateway_unreachable — have IPv4 but gateway ping fails (or no gateway).
    if not sample.get("default_gateway") or not sample.get("gateway_ping_ok"):
        return "gateway_unreachable"

    # wan_unreachable — gateway OK but public IPs fail.
    if not sample.get("internet_ping_ok"):
        return "wan_unreachable"

    # dns_only_failure — gateway + public OK but DNS fails.
    if not sample.get("dns_resolution_ok"):
        return "dns_only_failure"

    # possible_arp_conflict — gateway MAC changed unexpectedly.
    current_mac = sample.get("gateway_mac")
    if (
        expected_gateway_mac
        and current_mac
        and current_mac != expected_gateway_mac
    ):
        return "possible_arp_conflict"

    # possible_broadcast_storm — sharp rise in rx/tx errors+drops between polls.
    if prev_sample is not None:
        if _counters_spiked(prev_sample, sample):
            return "possible_broadcast_storm"

    # windows_unreachable_from_pi — Pi is otherwise healthy but Windows ping
    # fails. Lower severity per the spec's "Important Trigger Behavior".
    win_ok = sample.get("windows_ping_ok")
    if win_ok is False:
        return "windows_unreachable_from_pi"

    return "healthy"


def _counters_spiked(prev: Dict, cur: Dict) -> bool:
    """True if rx/tx errors (full counters) increased sharply between samples."""
    prev_full = prev.get("_counters_full") or {}
    cur_full = cur.get("_counters_full") or {}
    total_delta = 0
    for key in ("rx_errors", "tx_errors", "rx_dropped", "tx_dropped"):
        p = prev_full.get(key)
        c = cur_full.get(key)
        if isinstance(p, int) and isinstance(c, int) and c >= p:
            total_delta += c - p
    return total_delta >= SHARP_ERROR_DELTA


# A "degraded" sample is any non-healthy classification EXCEPT we still count
# windows_unreachable_from_pi as degraded so it can trigger its own (lower
# severity) event after the threshold — the spec wants it logged, not ignored.
def is_degraded(classification: str) -> bool:
    return classification != "healthy"


# Classifications that represent a *Pi-side* network failure (high severity).
PI_FAILURE_CLASSES = {
    "wifi_disconnected",
    "no_ipv4",
    "gateway_unreachable",
    "wan_unreachable",
    "dns_only_failure",
    "possible_arp_conflict",
    "possible_broadcast_storm",
}


# --------------------------------------------------------------------------- #
# Plain-English summaries (reflect the runbook interpretation guide)
# --------------------------------------------------------------------------- #
def plain_english(classification: str, sample: Dict) -> str:
    """Return a human-readable explanation for the given classification.

    The text mirrors the paired Windows+Pi interpretation matrix in the runbook
    so a human (or LLM) reading summary.json gets the right mental model.
    """
    win_ip = sample.get("windows_ping_ok")
    texts = {
        "wifi_disconnected": (
            "The Raspberry Pi lost Wi-Fi association with the access point. This "
            "points to a Wi-Fi / eero mesh side issue (radio, roaming, or AP "
            "problem) rather than something specific to the Windows desktop. If "
            "the Windows desktop is wired, this Pi-side Wi-Fi drop may be "
            "unrelated to the desktop's Ethernet outage."
        ),
        "no_ipv4": (
            "The Raspberry Pi is associated to Wi-Fi but has no IPv4 address. "
            "This suggests a DHCP problem (no lease from the eero/router) or a "
            "Wi-Fi link that is up at L2 but not usable at L3."
        ),
        "gateway_unreachable": (
            "The Raspberry Pi has Wi-Fi and an IPv4 address but cannot ping the "
            "default gateway. If the Windows desktop also cannot reach the "
            "gateway at the same time, this is most likely a LAN-wide "
            "eero/switch/topology or broadcast-storm issue. If the Pi is the only "
            "one affected, suspect the Wi-Fi path to the gateway."
        ),
        "wan_unreachable": (
            "The Raspberry Pi can reach the gateway but cannot reach public "
            "internet IPs (1.1.1.1 / 8.8.8.8). If the Windows desktop shows the "
            "same, this most likely indicates an eero WAN or Comcast upstream "
            "issue rather than a desktop-specific fault."
        ),
        "dns_only_failure": (
            "The Raspberry Pi can reach the gateway and public internet IPs, but "
            "DNS name resolution failed. If both devices show this, it is a DNS "
            "resolver / eero DNS / upstream DNS issue. If only the Pi sees it, "
            "suspect the Pi's resolver configuration."
        ),
        "windows_unreachable_from_pi": (
            "The Raspberry Pi remained connected to Wi-Fi and could reach the "
            "gateway, internet IPs, and DNS, but could not ping the Windows "
            "desktop. This suggests the outage was isolated to the desktop, its "
            "Ethernet NIC, its wired path, or its local firewall/sleep state "
            "rather than a whole-network outage. Note the desktop may simply be "
            "offline, asleep, or blocking ICMP, so this is not a definitive "
            "diagnosis on its own — compare with the Windows event folder."
        ),
        "possible_arp_conflict": (
            "The gateway's MAC address changed (or duplicate gateway entries were "
            "seen) around this event. Investigate duplicate IPs, ARP conflicts, "
            "gateway confusion, or topology instability."
        ),
        "possible_broadcast_storm": (
            "Interface error/drop counters rose sharply, consistent with a "
            "broadcast/multicast storm or a noisy device/loop on the LAN. Compare "
            "the tcpdump summary's top source MACs with the Windows desktop MAC."
        ),
        "healthy": (
            "All checks passed: the Raspberry Pi has Wi-Fi association, an IPv4 "
            "address, gateway reachability, internet reachability, working DNS, "
            "and (if configured) can reach the Windows desktop."
        ),
    }
    return texts.get(classification, "Unclassified network state.")


def suspicious_findings(classification: str, sample: Dict, mac_changed: bool) -> List[str]:
    """Return a short list of notable findings for summary.json."""
    findings: List[str] = []
    if classification == "windows_unreachable_from_pi":
        findings.append("Pi network remained healthy")
        findings.append("Windows desktop became unreachable from Wi-Fi vantage point")
    if classification == "wifi_disconnected":
        findings.append("Pi lost Wi-Fi association")
    if classification == "no_ipv4":
        findings.append("Pi has no IPv4 address (possible DHCP failure)")
    if classification == "gateway_unreachable":
        findings.append("Pi cannot reach the default gateway over Wi-Fi")
    if classification == "wan_unreachable":
        findings.append("Pi reaches gateway but not public internet IPs")
    if classification == "dns_only_failure":
        findings.append("Pi reaches internet IPs but DNS resolution failed")
    if classification == "possible_broadcast_storm":
        findings.append("Sharp rise in interface error/drop counters")
    if mac_changed:
        findings.append("Gateway MAC address changed around the event")
    if not findings:
        findings.append("No specific anomalies beyond the classification")
    return findings


def recommended_next_steps(classification: str) -> List[str]:
    """Return next-step suggestions tailored to the classification (runbook)."""
    common_compare = "Compare timestamp with Windows event folder"
    by_class = {
        "windows_unreachable_from_pi": [
            common_compare,
            "Test Windows desktop with USB Ethernet adapter",
            "Disable Windows Energy Efficient Ethernet and virtual bridge adapters",
            "Check managed switch counters if available",
        ],
        "gateway_unreachable": [
            common_compare,
            "Check whether Windows also lost the gateway (LAN-wide vs Pi-only)",
            "Inspect tcpdump summary for ARP/broadcast/multicast storm",
            "Check eero/switch health and uplinks",
        ],
        "wan_unreachable": [
            common_compare,
            "Confirm Windows shows the same WAN loss",
            "Check eero WAN status and Comcast modem",
        ],
        "dns_only_failure": [
            common_compare,
            "Check /etc/resolv.conf and eero DNS settings",
            "Compare whether Windows DNS also failed",
        ],
        "wifi_disconnected": [
            common_compare,
            "Check Wi-Fi signal and eero mesh health",
            "Review wpa_supplicant / NetworkManager journal logs",
        ],
        "no_ipv4": [
            common_compare,
            "Check DHCP leases on the eero",
            "Review wpa_supplicant / DHCP client journal logs",
        ],
        "possible_arp_conflict": [
            common_compare,
            "Investigate duplicate IPs and ARP table on the LAN",
            "Verify only one gateway is advertising the gateway IP",
        ],
        "possible_broadcast_storm": [
            common_compare,
            "Identify the noisy source MAC from the tcpdump summary",
            "Consider a managed switch with storm control / loop protection",
        ],
        "healthy": [
            "No action needed; snapshot captured for baseline comparison",
        ],
    }
    return by_class.get(classification, [common_compare])

"""Rolling state machine: degraded-sample detection and event classification.

Implements the spec's "Failure Detection" and "Event Classification" sections:

* :func:`is_degraded` evaluates a single sample against the previous one to decide
  whether this poll is degraded.
* :class:`StateMachine` tracks consecutive degraded counts and the event cooldown so an
  event snapshot fires after ``failure_threshold_count`` consecutive degraded samples and
  not more than once per ``event_cooldown_seconds``.
* :func:`classify` maps a sample (with optional history) to one of the spec's
  classification strings.
* :func:`plain_english` / :func:`recommended_next_steps` produce the human-readable
  ``summary.json`` text, drawing on the paired Windows+Pi runbook interpretation.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Degraded-sample detection
# ---------------------------------------------------------------------------

def is_degraded(sample: Dict[str, Any], previous: Optional[Dict[str, Any]]) -> Tuple[bool, List[str]]:
    """Return (degraded, reasons) for a single sample relative to ``previous``.

    Mirrors the spec's bullet list of degraded conditions.
    """
    reasons: List[str] = []

    if not sample.get("link_up", False):
        reasons.append("Ethernet link is down")
    if not sample.get("local_ipv4"):
        reasons.append("No local IPv4 address")
    if not sample.get("default_gateway"):
        reasons.append("No default gateway")
    if sample.get("default_gateway") and not sample.get("gateway_ping_ok", False):
        reasons.append("Gateway ping failed")
    if not sample.get("internet_ping_ok", False):
        reasons.append("All public IP pings failed")
    # DNS fails while IP ping succeeds -> DNS-only degraded condition.
    if sample.get("internet_ping_ok", False) and not sample.get("dns_resolution_ok", True):
        reasons.append("DNS resolution failed while internet ping succeeded")

    if previous is not None:
        # Sudden adapter error/discard increase.
        if _counter_increased(sample, previous, "adapter_rx_errors") or _counter_increased(
            sample, previous, "adapter_tx_errors"
        ):
            reasons.append("Adapter error counter increased during outage")
        if _counter_increased(sample, previous, "adapter_rx_discards") or _counter_increased(
            sample, previous, "adapter_tx_discards"
        ):
            reasons.append("Adapter discard counter increased during outage")
        # Gateway MAC changed unexpectedly.
        prev_mac = previous.get("gateway_mac")
        cur_mac = sample.get("gateway_mac")
        if prev_mac and cur_mac and prev_mac != cur_mac:
            reasons.append("Gateway MAC changed unexpectedly")
        # Local IP changed unexpectedly.
        prev_ip = previous.get("local_ipv4")
        cur_ip = sample.get("local_ipv4")
        if prev_ip and cur_ip and prev_ip != cur_ip:
            reasons.append("Local IP changed unexpectedly")
        # DNS server changed unexpectedly.
        prev_dns = previous.get("dns_servers") or []
        cur_dns = sample.get("dns_servers") or []
        if prev_dns and cur_dns and set(prev_dns) != set(cur_dns):
            reasons.append("DNS server changed unexpectedly")

    return (bool(reasons), reasons)


def _counter_increased(cur: Dict[str, Any], prev: Dict[str, Any], key: str) -> bool:
    """True if integer counter ``key`` increased from prev to cur (guards counter resets)."""
    try:
        c = int(cur.get(key, 0) or 0)
        p = int(prev.get(key, 0) or 0)
    except (TypeError, ValueError):
        return False
    return c > p


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------

def classify(sample: Dict[str, Any], history: Optional[List[Dict[str, Any]]] = None) -> str:
    """Classify a sample into one of the spec's classification strings.

    Priority order follows the spec's logic top-down.
    """
    history = history or []

    link_up = sample.get("link_up", False)
    has_ipv4 = bool(sample.get("local_ipv4"))
    gw_ok = sample.get("gateway_ping_ok", False)
    inet_ok = sample.get("internet_ping_ok", False)
    dns_ok = sample.get("dns_resolution_ok", True)
    pi_ok = sample.get("pi_ping_ok")

    # possible_arp_conflict: gateway MAC changed across recent history.
    if _gateway_mac_changed(sample, history):
        return "possible_arp_conflict"

    if not link_up:
        return "link_down"
    if not has_ipv4:
        return "no_ipv4"
    if not gw_ok:
        return "gateway_unreachable"
    if gw_ok and not inet_ok:
        return "wan_unreachable"
    if gw_ok and inet_ok and not dns_ok:
        return "dns_only_failure"

    # lan_partial_failure: gateway inconsistent across history AND Pi ping fails.
    if pi_ok is False and _gateway_inconsistent(sample, history):
        return "lan_partial_failure"

    # possible_adapter_driver_issue: link up but counters show errors/discards/reset.
    if link_up and _adapter_errors_present(sample, history):
        return "possible_adapter_driver_issue"

    return "healthy"


def _gateway_mac_changed(sample: Dict[str, Any], history: List[Dict[str, Any]]) -> bool:
    macs = [h.get("gateway_mac") for h in history if h.get("gateway_mac")]
    cur = sample.get("gateway_mac")
    if cur:
        macs.append(cur)
    distinct = {m for m in macs if m}
    return len(distinct) > 1


def _gateway_inconsistent(sample: Dict[str, Any], history: List[Dict[str, Any]]) -> bool:
    results = [bool(h.get("gateway_ping_ok")) for h in history]
    results.append(bool(sample.get("gateway_ping_ok")))
    return len(set(results)) > 1  # mix of pass/fail = inconsistent/flapping


def _adapter_errors_present(sample: Dict[str, Any], history: List[Dict[str, Any]]) -> bool:
    if not history:
        return False
    prev = history[-1]
    return (
        _counter_increased(sample, prev, "adapter_rx_errors")
        or _counter_increased(sample, prev, "adapter_tx_errors")
        or _counter_increased(sample, prev, "adapter_rx_discards")
        or _counter_increased(sample, prev, "adapter_tx_discards")
    )


# ---------------------------------------------------------------------------
# State machine
# ---------------------------------------------------------------------------

@dataclass
class StateMachine:
    """Tracks consecutive degraded samples and event cooldown."""

    failure_threshold_count: int
    event_cooldown_seconds: float

    consecutive_degraded: int = 0
    last_event_time: float = field(default=0.0)
    previous_sample: Optional[Dict[str, Any]] = None

    def update(self, sample: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """Feed a sample. Return (should_trigger_event, degraded_reasons).

        Triggers when consecutive degraded samples reach the threshold AND the cooldown
        has elapsed since the last event.
        """
        degraded, reasons = is_degraded(sample, self.previous_sample)
        self.previous_sample = sample

        if degraded:
            self.consecutive_degraded += 1
        else:
            self.consecutive_degraded = 0
            return (False, reasons)

        if self.consecutive_degraded < self.failure_threshold_count:
            return (False, reasons)

        now = time.monotonic()
        if (now - self.last_event_time) < self.event_cooldown_seconds and self.last_event_time > 0:
            return (False, reasons)  # within cooldown; suppress duplicate event

        self.last_event_time = now
        return (True, reasons)


# ---------------------------------------------------------------------------
# Human-readable text for summary.json
# ---------------------------------------------------------------------------

_PLAIN_ENGLISH: Dict[str, str] = {
    "link_down": (
        "The Ethernet adapter reported link DOWN. The cable/port appears electrically "
        "disconnected to Windows. Suspect NIC power management, cable/port, or driver "
        "resetting the link."
    ),
    "no_ipv4": (
        "Ethernet link was up but Windows had no IPv4 address. This points to DHCP failure, "
        "an IP/address conflict, or APIPA fallback rather than a pure routing problem."
    ),
    "gateway_unreachable": (
        "Ethernet link and local IP were present, but the desktop could not reach the default "
        "gateway. This points to desktop NIC/driver, wired LAN path, switch/eero LAN, ARP, or "
        "local broadcast storm rather than DNS-only failure."
    ),
    "wan_unreachable": (
        "The desktop could reach the gateway but not public internet IPs. This points to a "
        "WAN/eero/Comcast routing problem rather than a desktop-local issue. Compare with the "
        "Raspberry Pi: if the Pi shows the same, it is almost certainly WAN/Comcast/eero."
    ),
    "dns_only_failure": (
        "Gateway and public IP pings worked, but DNS name resolution failed. This is a DNS-only "
        "issue. If the Pi resolves fine at the same time, suspect a Windows DNS client / VPN / "
        "proxy issue; if the Pi also fails, suspect the eero/upstream DNS resolver."
    ),
    "lan_partial_failure": (
        "Gateway reachability was inconsistent (flapping) and the Raspberry Pi cross-ping failed. "
        "This suggests a partial LAN path problem on the wired side toward the switch/eero rather "
        "than a clean total outage."
    ),
    "possible_arp_conflict": (
        "The gateway MAC address changed or duplicate gateway entries were observed around the "
        "outage. Investigate duplicate IPs, ARP conflicts/poisoning, or topology weirdness "
        "(e.g. a loop or a second device answering for the gateway IP)."
    ),
    "possible_adapter_driver_issue": (
        "The Ethernet link stayed up, but adapter error/discard counters increased (or the "
        "adapter appears to have reset). This points to the NIC driver / motherboard NIC hardware "
        "or aggressive offload/power-saving features."
    ),
    "healthy": "All checks passed at the time of this snapshot.",
}


def plain_english(classification: str) -> str:
    return _PLAIN_ENGLISH.get(classification, "Network degraded; see samples for detail.")


def suspicious_findings(sample: Dict[str, Any], history: List[Dict[str, Any]], reasons: List[str]) -> List[str]:
    """Build the ``suspicious_findings`` list combining degraded reasons + adapter flags."""
    findings: List[str] = list(dict.fromkeys(reasons))  # de-dup, preserve order

    # Surface suspicious virtual/bridge/VPN adapters present at event time.
    for adp in sample.get("suspicious_adapters", []) or []:
        findings.append(
            f"Suspicious adapter present: {adp.get('name')} "
            f"({adp.get('description')}) [{', '.join(adp.get('reasons', []))}]"
        )

    # Storm heuristic: tx growing far faster than rx during the window.
    if _tx_outpaces_rx(sample, history):
        findings.append(
            "Outbound packet/byte volume grew much faster than inbound during the window "
            "(possible desktop-originated broadcast/multicast storm)"
        )
    return findings


def _tx_outpaces_rx(sample: Dict[str, Any], history: List[Dict[str, Any]]) -> bool:
    if not history:
        return False
    first = history[0]
    try:
        d_tx = int(sample.get("adapter_tx_bytes", 0)) - int(first.get("adapter_tx_bytes", 0))
        d_rx = int(sample.get("adapter_rx_bytes", 0)) - int(first.get("adapter_rx_bytes", 0))
    except (TypeError, ValueError):
        return False
    # Heuristic: meaningful tx delta and tx >> rx.
    return d_tx > 5_000_000 and d_tx > (d_rx * 5 + 1)


def recommended_next_steps(classification: str) -> List[str]:
    """Return next-step guidance, tailored by classification, drawn from the runbook."""
    common = [
        "Test with a USB 3.0 Gigabit Ethernet adapter and disable the motherboard NIC",
        "Disable Energy Efficient Ethernet / Green Ethernet and power-saving on the NIC",
        "Check Hyper-V, Docker, WSL, VPN, and Network Bridge adapters",
        "Compare with the Raspberry Pi event at the same timestamp",
    ]
    extra: Dict[str, List[str]] = {
        "gateway_unreachable": [
            "Bypass the 24-port switch: connect the desktop directly to the gateway eero",
            "Boot a Linux live USB and retest Ethernet to isolate Windows driver vs hardware",
        ],
        "wan_unreachable": [
            "Confirm the Pi sees the same WAN failure (then it is Comcast/eero, not the desktop)",
            "Check the eero app / Comcast modem status lights",
        ],
        "dns_only_failure": [
            "Run 'ipconfig /flushdns' and compare DNS behavior with the Pi",
            "Check for VPN/proxy DNS interception and the configured DNS servers",
        ],
        "possible_arp_conflict": [
            "Look for duplicate IPs / a second device answering for the gateway IP",
            "Check the eero app for IP reservation conflicts",
        ],
        "possible_adapter_driver_issue": [
            "Update or roll back the NIC driver (Intel/Realtek/Killer)",
            "Disable Large Send Offload, Flow Control, and Interrupt Moderation as a test",
        ],
        "link_down": [
            "Inspect 'Allow the computer to turn off this device to save power' in Device Manager",
        ],
        "no_ipv4": [
            "Check DHCP / eero reservations and look for IP address conflicts",
        ],
        "lan_partial_failure": [
            "Consider a managed switch with STP/loop protection and storm control to find a noisy port",
        ],
    }
    return extra.get(classification, []) + common

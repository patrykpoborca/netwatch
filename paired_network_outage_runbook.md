# Home Network Outage Logging — Paired Windows + Raspberry Pi Runbook

## Purpose

This runbook explains how to use two diagnostic watchdogs together:

1. **Windows Ethernet Watchdog** on the affected desktop.
2. **Raspberry Pi Wi-Fi Watchdog** on an always-on Raspberry Pi.

The purpose is to capture the same outage from two network vantage points:

```text
Windows desktop over Ethernet
Raspberry Pi over Wi-Fi
```

This helps classify whether the failure is:

- desktop-only,
- wired-only,
- LAN-wide,
- DNS-only,
- WAN/Comcast/eero-related,
- or caused by broadcast/multicast/ARP/DHCP storm behavior.

---

## Known Network Topology

Confirmed topology:

```text
Comcast modem → gateway eero → 24-port switch → wired network / wired eeros / Windows desktop
```

The issue has happened on:

- different floors,
- different wall ports,
- different switch ports,
- different Ethernet cables.

Therefore, a single bad cable, wall jack, or switch port is less likely.

---

## Recommended Static DHCP Reservations

In the eero app, reserve IPs for:

```text
Windows desktop: e.g. 192.168.4.50
Raspberry Pi:    e.g. 192.168.4.25
```

Use the actual IP range from the home network.

Then configure:

- Windows app `raspberry_pi_ip`
- Pi app `windows_desktop_ip`

This allows both devices to cross-ping each other.

---

## Time Synchronization

Make sure both devices have correct time.

On Windows:

```powershell
w32tm /query /status
```

On Raspberry Pi:

```bash
timedatectl status
```

The logs are only useful if timestamps line up.

---

## What to Compare During an Outage

Find event folders with the same timestamp window.

Windows:

```text
C:\NetworkSnapshots\events\
```

Raspberry Pi:

```text
/var/log/netwatch-pi/events/
```

Compare:

```text
summary.json
recent_samples.jsonl
packet capture summaries
gateway MAC
local IP
DNS server
gateway ping result
public IP ping result
DNS resolution result
cross-ping result
```

---

## Interpretation Matrix

| Windows Result | Pi Result | Likely Meaning |
|---|---|---|
| Windows cannot ping gateway | Pi can ping gateway + internet | Desktop NIC/driver/Windows stack/wired path |
| Windows cannot ping gateway | Pi also cannot ping gateway | LAN-wide eero/switch/storm/topology issue |
| Windows can ping gateway, cannot ping 1.1.1.1 | Pi has same issue | WAN/eero/Comcast issue |
| Windows can ping 1.1.1.1, DNS fails | Pi has same issue | DNS issue |
| Windows can ping 1.1.1.1, DNS fails | Pi DNS works | Windows DNS/client/VPN/proxy issue |
| Windows gateway MAC changes | Pi gateway MAC stable or changed | Possible ARP/gateway conflict |
| Pi healthy, Windows unreachable from Pi | Desktop isolated, asleep, firewall, NIC, or wired side |
| Pi sees ARP/DHCP/mDNS/SSDP flood | Windows or another device may be noisy |
| Both logs show high broadcast/multicast | LAN storm or loop likely |

---

## Most Useful First Questions

When the outage happens, answer these:

### 1. Is the Pi healthy?

If yes, the problem is probably not Comcast or the whole eero network.

### 2. Can the Pi ping the desktop?

If no, while Pi is otherwise healthy, the problem is probably isolated to the desktop or wired side.

### 3. Can the Windows desktop ping the gateway?

If no, it is not a pure DNS problem.

### 4. Can Windows ping `1.1.1.1` but not resolve names?

If yes, it is likely DNS-specific.

### 5. Did the gateway MAC change?

If yes, investigate duplicate IPs, ARP conflicts, or topology weirdness.

### 6. Did packet volume spike before the failure?

If yes, suspect a storm/noisy service/loop.

---

## Practical Follow-Up Tests

Run these in order.

### Test 1 — Disable Windows NIC Power Features

In Device Manager → Network Adapter → Properties:

Disable temporarily:

```text
Energy Efficient Ethernet
Green Ethernet
Allow the computer to turn off this device to save power
Large Send Offload IPv4
Large Send Offload IPv6
Flow Control
Interrupt Moderation
```

Not all adapters have all options.

### Test 2 — Check Windows Virtual Networking

Look for and temporarily disable:

```text
Hyper-V virtual switches
Docker/WSL virtual adapters
VPN adapters
Network Bridge
Internet Connection Sharing
Killer/Realtek/ASUS/MSI network optimizer utilities
```

### Test 3 — USB Ethernet Adapter

Use a USB 3.0 gigabit Ethernet adapter and disable the motherboard Ethernet adapter.

If the issue disappears, suspect:

```text
motherboard NIC hardware or driver
```

### Test 4 — Linux Live USB

Boot the desktop into Ubuntu live USB and use Ethernet.

If the issue disappears, suspect:

```text
Windows driver/software/virtual adapter
```

If it continues, suspect:

```text
NIC hardware or switch/eero interaction
```

### Test 5 — Bypass the 24-Port Switch

Temporarily connect the desktop directly to the LAN side of the gateway eero.

If the issue disappears, suspect:

```text
switch + desktop interaction
```

If it continues, suspect:

```text
desktop NIC/driver/eero interaction
```

### Test 6 — Managed Switch

If evidence points to storms or loops, replace the unmanaged switch with a managed switch supporting:

```text
RSTP/STP
loop protection
storm control
per-port counters
port mirroring
```

This can identify the exact noisy port/device.

---

## What Good Evidence Looks Like

### Desktop-only failure

```text
Pi:
  gateway ping OK
  internet ping OK
  DNS OK
  Windows ping failed

Windows:
  link up
  local IP present
  gateway ping failed
```

Likely diagnosis:

```text
Windows NIC/driver/software stack or wired desktop path
```

### DNS-only failure

```text
Windows:
  gateway ping OK
  1.1.1.1 ping OK
  DNS failed

Pi:
  gateway ping OK
  1.1.1.1 ping OK
  DNS failed
```

Likely diagnosis:

```text
DNS resolver/eero DNS/upstream DNS issue
```

### WAN/Comcast failure

```text
Windows:
  gateway ping OK
  1.1.1.1 failed

Pi:
  gateway ping OK
  1.1.1.1 failed
```

Likely diagnosis:

```text
eero WAN or Comcast issue
```

### LAN-wide storm/topology failure

```text
Windows:
  gateway ping failed

Pi:
  gateway ping failed

Packet summaries:
  high ARP/broadcast/multicast
```

Likely diagnosis:

```text
LAN storm, loop, eero/switch issue, or noisy wired device
```

---

## How to Package Evidence

When asking another person/LLM/vendor to analyze, provide:

```text
1. Windows summary.json
2. Pi summary.json
3. Windows recent_samples.jsonl around the event
4. Pi recent_samples.jsonl around the event
5. tcpdump_summary.txt from Pi
6. Windows pktmon_capture.pcapng if small enough
7. Pi tcpdump_capture.pcap if small enough
8. Exact time the human noticed the outage
9. Whether unplug/replug Ethernet fixed it
10. Whether Wi-Fi devices still worked during the event
```

Avoid sending huge packet captures publicly unless reviewed for privacy. Packet captures may contain hostnames, DNS queries, local IPs, MAC addresses, and some metadata.

---

## Privacy Notes

The tools should not upload anything automatically.

Captured data may include:

- local IP addresses,
- MAC addresses,
- DNS queries,
- hostnames,
- device names,
- local service discovery traffic,
- connection metadata.

Keep logs local unless intentionally sharing for troubleshooting.

---

## Desired End State

After one or two events, the paired logs should tell you which branch you are in:

```text
A. Desktop/NIC/Windows-only
B. Wired LAN/switch side
C. LAN-wide eero/switch/storm
D. WAN/Comcast
E. DNS-only
```

From there, the fix path becomes much clearer.

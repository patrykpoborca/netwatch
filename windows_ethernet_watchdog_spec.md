# Windows Ethernet Watchdog — Technical Specification

## Goal

Build a Windows logging application that continuously observes the desktop computer's Ethernet network health and captures a rich diagnostic snapshot when the failure occurs.

The user's observed issue:

- Desktop is connected by Ethernet.
- Periodically the desktop loses internet/network connectivity.
- Connectivity recovers after unplugging and replugging Ethernet.
- The issue has occurred across different rooms, wall ports, switch ports, and Ethernet cables.
- Network topology is confirmed as:

```text
Comcast modem → gateway eero → 24-port switch → wired home network / wired eeros / desktop
```

This makes a single bad cable, single wall jack, or single switch port less likely. The leading suspects are:

1. Windows desktop NIC driver/software stack.
2. Motherboard Ethernet NIC hardware.
3. Desktop-originated ARP/DHCP/mDNS/SSDP/DNS/broadcast/multicast storm.
4. Unmanaged switch failing to contain a noisy desktop.
5. eero/switch interaction.
6. DNS-only issue, possible but not the leading hypothesis.

The app must help classify whether the outage is:

- Local NIC/link failure.
- Wired LAN failure.
- LAN-wide gateway failure.
- WAN/Comcast/eero internet failure.
- DNS-only failure.
- Broadcast/multicast storm.
- DHCP/IP/ARP conflict.
- Windows virtual adapter or bridge issue.

---

## Implementation Preference

Use Python 3.11+ for orchestration.

PowerShell commands may be invoked from Python for Windows-specific network state.

The app should be runnable manually first, then optionally installed as a Windows Scheduled Task or service.

Recommended project name:

```text
netwatch-windows
```

---

## Operating Requirements

- Windows 10 or Windows 11.
- Must run with Administrator privileges for full diagnostic capture.
- No cloud dependencies.
- No external API calls.
- Local-only logging.
- Should work even when internet is down.
- Should degrade gracefully if a command is unavailable.
- Should never auto-repair the network unless explicitly started with a `--repair` flag.

---

## Configuration File

Use a local config file:

```text
config.json
```

Example:

```json
{
  "host_label": "gaming-desktop",
  "preferred_interface_alias": "Ethernet",
  "raspberry_pi_ip": "192.168.4.25",
  "gateway_ip_override": null,
  "poll_interval_seconds": 5,
  "failure_threshold_count": 3,
  "event_cooldown_seconds": 300,
  "packet_capture_seconds": 60,
  "output_dir": "C:\\NetworkSnapshots",
  "jsonl_log_path": "C:\\NetworkSnapshots\\netwatch-windows.jsonl",
  "targets": {
    "internet_ips": ["1.1.1.1", "8.8.8.8"],
    "dns_names": ["google.com", "cloudflare.com"]
  },
  "enable_pktmon_capture": true,
  "enable_netsh_trace_fallback": true,
  "repair_enabled": false
}
```

If `gateway_ip_override` is null, detect default gateway automatically.

If `raspberry_pi_ip` is null or unavailable, skip Pi ping check.

---

## Runtime Behavior

Every `poll_interval_seconds`, collect a lightweight health sample.

A sample should include:

```json
{
  "timestamp": "2026-06-07T22:41:03.123-05:00",
  "host_label": "gaming-desktop",
  "os": "Windows",
  "interface_alias": "Ethernet",
  "interface_description": "Intel(R) Ethernet Controller ...",
  "local_ipv4": "192.168.4.50",
  "default_gateway": "192.168.4.1",
  "dns_servers": ["192.168.4.1"],
  "link_up": true,
  "link_speed": "1 Gbps",
  "gateway_ping_ok": true,
  "internet_ping_ok": true,
  "dns_resolution_ok": true,
  "pi_ping_ok": true,
  "gateway_mac": "aa-bb-cc-dd-ee-ff",
  "adapter_rx_bytes": 12345678,
  "adapter_tx_bytes": 23456789,
  "adapter_rx_errors": 0,
  "adapter_tx_errors": 0,
  "classification": "healthy"
}
```

Append every sample as one line to:

```text
C:\NetworkSnapshots\netwatch-windows.jsonl
```

Use JSON Lines, one object per line.

---

## Health Checks

Perform these checks in every polling cycle.

### 1. Detect Active Ethernet Adapter

Use PowerShell:

```powershell
Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
Get-NetIPConfiguration
```

Prefer the configured `preferred_interface_alias` if present.

Log all active adapters, including virtual adapters.

Explicitly flag suspicious adapters:

- Hyper-V Virtual Ethernet Adapter
- Docker
- WSL
- VPN adapters
- TAP/TUN adapters
- Network Bridge
- Internet Connection Sharing-related adapters

### 2. Link State

Capture:

```powershell
Get-NetAdapter -Name "<alias>" | Format-List *
Get-NetAdapterStatistics -Name "<alias>"
Get-NetAdapterAdvancedProperty -Name "<alias>"
```

Important fields:

- Status
- LinkSpeed
- MacAddress
- DriverInformation
- InterfaceDescription
- ReceivedBytes
- SentBytes
- ReceivedUnicastPackets
- SentUnicastPackets
- ReceivedDiscardedPackets
- OutboundDiscardedPackets
- ReceivedPacketErrors
- OutboundPacketErrors

### 3. Gateway Ping

Ping the default gateway:

```powershell
Test-Connection -ComputerName <gateway-ip> -Count 2 -Quiet
```

If gateway ping fails, this suggests local NIC, wired LAN, switch, eero LAN, ARP, or storm issue.

### 4. Internet IP Ping

Ping public IPs, preferably both:

```powershell
Test-Connection -ComputerName 1.1.1.1 -Count 2 -Quiet
Test-Connection -ComputerName 8.8.8.8 -Count 2 -Quiet
```

If gateway works but public IP ping fails, suspect WAN/eero/Comcast routing.

### 5. DNS Resolution

Resolve:

```powershell
Resolve-DnsName google.com -ErrorAction SilentlyContinue
Resolve-DnsName cloudflare.com -ErrorAction SilentlyContinue
```

If IP ping works but DNS resolution fails, classify as DNS-only failure.

### 6. Raspberry Pi Cross-Ping

If configured:

```powershell
Test-Connection -ComputerName <raspberry-pi-ip> -Count 2 -Quiet
```

This helps determine whether wired desktop can reach the Wi-Fi vantage point.

### 7. Gateway ARP / Neighbor Entry

Capture gateway MAC:

```powershell
Get-NetNeighbor -IPAddress <gateway-ip>
arp -a
```

If gateway MAC changes during/near outage, flag possible gateway conflict, ARP poisoning, duplicate IP, or topology issue.

---

## Failure Detection

Maintain a rolling state machine.

A poll is considered degraded if any of the following are true:

- Ethernet link is down.
- No local IPv4 address.
- No default gateway.
- Gateway ping fails.
- Both public IP pings fail.
- DNS resolution fails while IP ping succeeds.
- Adapter counters show sudden errors/discards.
- Gateway MAC changes unexpectedly.
- Local IP changes unexpectedly.
- DNS server changes unexpectedly.

Trigger an event snapshot after:

```text
failure_threshold_count consecutive degraded samples
```

Default: 3 consecutive failures.

Use an event cooldown to avoid creating hundreds of event folders during one outage.

Default:

```text
event_cooldown_seconds = 300
```

---

## Event Classification

Set `classification` in `summary.json` using this logic:

```text
link_down:
  Ethernet adapter reports link down.

no_ipv4:
  Link is up but no IPv4 address exists.

gateway_unreachable:
  Link and IPv4 exist, but default gateway ping fails.

wan_unreachable:
  Gateway ping works, but public IP pings fail.

dns_only_failure:
  Gateway and public IP pings work, but DNS resolution fails.

lan_partial_failure:
  Gateway ping works/fails inconsistently and Pi ping fails.

possible_arp_conflict:
  Gateway MAC changed or duplicate gateway entries are observed.

possible_adapter_driver_issue:
  Link remains up but counters show errors/discards or sudden reset.

healthy:
  All checks pass.
```

---

## Event Snapshot Folder

On trigger, create:

```text
C:\NetworkSnapshots\events\YYYY-MM-DD_HH-mm-ss_windows_<classification>\
```

Write these files:

```text
summary.json
recent_samples.jsonl
ipconfig_all.txt
route_print.txt
arp_a.txt
get_net_adapter.txt
get_net_adapter_statistics.txt
get_net_adapter_advanced_property.txt
get_net_ip_configuration.txt
get_net_neighbor.txt
dns_client_server_address.txt
dns_client_cache.txt
active_connections.txt
network_eventlog_system.txt
network_eventlog_application.txt
pktmon_capture.pcapng
pktmon_raw.etl
command_errors.json
```

---

## Commands to Capture

### Basic State

```powershell
ipconfig /all
route print
arp -a
netstat -ano
```

### PowerShell Network State

```powershell
Get-NetAdapter | Format-List *
Get-NetAdapterStatistics | Format-List *
Get-NetAdapterAdvancedProperty | Format-List *
Get-NetIPConfiguration | Format-List *
Get-NetNeighbor | Format-Table -AutoSize
Get-DnsClientServerAddress | Format-List *
Get-DnsClientCache
Get-NetRoute | Format-Table -AutoSize
Get-NetIPInterface | Format-List *
```

### Suspicious Sharing / Bridge State

```powershell
Get-NetAdapterBinding | Format-Table -AutoSize
Get-NetConnectionProfile | Format-List *
Get-Service SharedAccess
```

Also check for bridge adapters by name:

```powershell
Get-NetAdapter | Where-Object { $_.Name -like "*Bridge*" -or $_.InterfaceDescription -like "*Bridge*" }
```

### Event Logs

Capture recent network-adjacent events:

```powershell
Get-WinEvent -LogName System -MaxEvents 300 |
  Where-Object {
    $_.ProviderName -match "Tcpip|Dhcp|DNS|Netwtw|e1|Realtek|NDIS|WLAN|NetworkProfile|Kernel-Network"
  } |
  Format-List *
```

Also capture broad recent system events:

```powershell
Get-WinEvent -LogName System -MaxEvents 300 | Format-List *
```

---

## Packet Capture

### Preferred: pktmon

On event trigger:

```powershell
pktmon filter remove
pktmon filter add -p 53
pktmon filter add -p 67
pktmon filter add -p 68
pktmon start --capture --pkt-size 0 --comp nics
Start-Sleep -Seconds 60
pktmon stop
pktmon etl2pcap PktMon.etl --out pktmon_capture.pcapng
```

Also consider a no-filter capture if the above is too narrow:

```powershell
pktmon filter remove
pktmon start --capture --pkt-size 0 --comp nics
```

Keep the capture short to avoid huge files.

### Fallback: netsh trace

If pktmon fails:

```powershell
netsh trace start capture=yes report=no persistent=no tracefile=netsh_trace.etl
Start-Sleep -Seconds 60
netsh trace stop
```

---

## Broadcast / Storm Detection Heuristics

Without full packet parsing, approximate storm suspicion from counters:

- Extremely high outbound packet rate from desktop.
- Rapid increase in broadcast/multicast packets if available.
- Adapter sent packets grows much faster than received packets during outage.
- Pi simultaneously reports gateway issues.
- Gateway ARP changes or flaps.

If Scapy or PyShark is available, optionally parse captures for:

- Top source MAC addresses.
- Top destination MAC addresses.
- Broadcast frame count.
- Multicast frame count.
- ARP packet count.
- DHCP packet count.
- DNS query count.
- mDNS `224.0.0.251:5353`.
- SSDP `239.255.255.250:1900`.
- LLMNR `224.0.0.252:5355`.
- NetBIOS `udp/137`.

Do not make packet parsing mandatory for v1.

---

## Optional Repair Mode

Default behavior must be logging-only.

If started with:

```text
--repair
```

and `repair_enabled` is true, allow manually requested actions:

```powershell
ipconfig /renew
ipconfig /flushdns
Disable-NetAdapter -Name "<alias>" -Confirm:$false
Start-Sleep -Seconds 3
Enable-NetAdapter -Name "<alias>" -Confirm:$false
```

Before running repair, snapshot first.

After repair, snapshot again.

Never auto-repair without explicit flag.

---

## CLI

Support:

```text
python netwatch_windows.py run
python netwatch_windows.py snapshot
python netwatch_windows.py classify-latest
python netwatch_windows.py install-task
python netwatch_windows.py uninstall-task
python netwatch_windows.py run --repair
```

### `run`

Runs continuous watchdog.

### `snapshot`

Immediately creates a diagnostic snapshot even if network is healthy.

### `classify-latest`

Reads the latest event folder and prints likely diagnosis.

### `install-task`

Creates a Windows Scheduled Task to run at login or startup.

### `uninstall-task`

Removes the Scheduled Task.

---

## Scheduled Task Install

Generate a helper PowerShell script:

```powershell
$Action = New-ScheduledTaskAction -Execute "python" -Argument "C:\NetworkWatch\netwatch_windows.py run"
$Trigger = New-ScheduledTaskTrigger -AtStartup
$Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
Register-ScheduledTask -TaskName "NetworkWatchWindows" -Action $Action -Trigger $Trigger -Principal $Principal
```

If running as SYSTEM complicates paths, alternatively install for the current user with highest privileges.

---

## Expected Output Summary

`summary.json` should be human-readable and include:

```json
{
  "event_id": "2026-06-07_22-41-03_windows_gateway_unreachable",
  "host_label": "gaming-desktop",
  "classification": "gateway_unreachable",
  "plain_english": "Ethernet link and local IP were present, but the desktop could not reach the default gateway. This points to desktop NIC/driver, wired LAN path, switch/eero LAN, ARP, or local broadcast storm rather than DNS-only failure.",
  "local_ip_before": "192.168.4.50",
  "local_ip_after": "192.168.4.50",
  "gateway_ip": "192.168.4.1",
  "gateway_mac_before": "aa-bb-cc-dd-ee-ff",
  "gateway_mac_after": "aa-bb-cc-dd-ee-ff",
  "dns_servers": ["192.168.4.1"],
  "internet_ip_ping_ok": false,
  "dns_resolution_ok": false,
  "pi_ping_ok": false,
  "suspicious_findings": [
    "Gateway ping failed while Ethernet link remained up",
    "Adapter error counter increased during outage"
  ],
  "recommended_next_steps": [
    "Test with USB Ethernet adapter",
    "Disable Energy Efficient Ethernet / Green Ethernet",
    "Check Hyper-V, Docker, VPN, and bridge adapters",
    "Compare with Raspberry Pi event at same timestamp"
  ]
}
```

---

## README Interpretation Guide

Include this in the generated project's README:

```text
How to interpret paired Windows + Raspberry Pi results:

1. Windows cannot ping gateway, Pi can ping gateway and internet:
   Most likely desktop NIC, Windows driver, virtual adapter, wired path, or switch port path.

2. Windows and Pi both cannot ping gateway:
   Most likely LAN-wide eero/switch issue, broadcast storm, topology loop, or gateway eero problem.

3. Windows can ping gateway and 1.1.1.1, but DNS fails:
   DNS-only issue.

4. Windows can ping gateway but not 1.1.1.1, and Pi has same issue:
   WAN/eero/Comcast issue.

5. Gateway MAC changes around outage:
   Possible ARP conflict, duplicate IP, gateway confusion, or topology issue.

6. Desktop outbound packet rate spikes before outage:
   Possible desktop-originated storm or noisy service.

7. Problem disappears with USB Ethernet adapter:
   Strong evidence for motherboard NIC driver or hardware issue.

8. Problem disappears in Linux live USB:
   Strong evidence for Windows driver/software/virtual adapter issue.
```

---

## Acceptance Criteria

The generated app is successful when:

- It runs continuously without crashing.
- It writes JSONL samples every poll.
- It detects and snapshots degraded network states.
- It captures useful Windows network state.
- It captures a packet trace when possible.
- It never depends on internet access to log.
- It creates timestamped event folders.
- Its `summary.json` gives a clear classification and next steps.
- Logs from Windows can be compared by timestamp with Raspberry Pi logs.

---

## Stretch Goals

- Lightweight tray icon with current status.
- Local web dashboard.
- Automatic compression of old event folders.
- Export latest event as ZIP.
- Optional Discord/Slack/email alert only after network returns.
- Optional Wireshark-compatible summary report.

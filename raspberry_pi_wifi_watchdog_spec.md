# Raspberry Pi Wi-Fi Watchdog — Technical Specification

## Goal

Build a Raspberry Pi logging application that continuously observes home network health from the Wi-Fi side and captures a rich diagnostic snapshot when the desktop Ethernet failure occurs or when the Pi itself sees a network failure.

The Pi is an always-on Wi-Fi vantage point. It should help determine whether the outage is isolated to the Windows desktop/wired side or affects the whole LAN/eero/WAN.

Known network context:

```text
Comcast modem → gateway eero → 24-port switch → wired home network / wired eeros / desktop
```

The Windows desktop periodically loses connectivity over Ethernet and recovers after unplugging/replugging Ethernet.

The Pi should answer:

- Does Wi-Fi still reach the gateway when Windows Ethernet fails?
- Does Wi-Fi still reach the internet?
- Does DNS still work?
- Does the Pi observe ARP/DHCP/DNS/multicast/broadcast spikes during the event?
- Does the gateway MAC change?
- Does the Pi lose Wi-Fi association or only WAN connectivity?
- Can the Pi still ping the Windows desktop?

---

## Implementation Preference

Use Python 3.11+.

Use shell commands for Linux network diagnostics.

Recommended project name:

```text
netwatch-pi
```

---

## Operating Requirements

- Raspberry Pi OS or Debian-like Linux.
- Python 3.11+.
- Runs as a systemd service.
- Uses Wi-Fi as primary vantage point.
- Must work without internet.
- Writes local logs.
- Should degrade gracefully if optional tools are unavailable.
- For packet captures, the service needs permission to run `tcpdump`, likely via root/systemd.

---

## Suggested Packages

Install:

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip iproute2 dnsutils tcpdump wireless-tools iw network-manager
```

Some systems may not use NetworkManager. The app should still work if `nmcli` is absent.

---

## Configuration File

Use:

```text
/etc/netwatch-pi/config.json
```

Example:

```json
{
  "host_label": "raspberry-pi-wifi",
  "preferred_interface": "wlan0",
  "windows_desktop_ip": "192.168.4.50",
  "gateway_ip_override": null,
  "poll_interval_seconds": 5,
  "failure_threshold_count": 3,
  "event_cooldown_seconds": 300,
  "packet_capture_seconds": 60,
  "output_dir": "/var/log/netwatch-pi",
  "jsonl_log_path": "/var/log/netwatch-pi/netwatch-pi.jsonl",
  "targets": {
    "internet_ips": ["1.1.1.1", "8.8.8.8"],
    "dns_names": ["google.com", "cloudflare.com"]
  },
  "enable_tcpdump_capture": true
}
```

If `gateway_ip_override` is null, detect the default gateway with:

```bash
ip route show default
```

If `windows_desktop_ip` is null, skip Windows ping check.

---

## Runtime Behavior

Every `poll_interval_seconds`, write a lightweight JSONL sample.

Example sample:

```json
{
  "timestamp": "2026-06-07T22:41:03.123-05:00",
  "host_label": "raspberry-pi-wifi",
  "os": "Linux",
  "interface": "wlan0",
  "local_ipv4": "192.168.4.25",
  "default_gateway": "192.168.4.1",
  "dns_servers": ["192.168.4.1"],
  "wifi_associated": true,
  "wifi_ssid": "HomeNetwork",
  "wifi_signal_dbm": -52,
  "gateway_ping_ok": true,
  "internet_ping_ok": true,
  "dns_resolution_ok": true,
  "windows_ping_ok": true,
  "gateway_mac": "aa:bb:cc:dd:ee:ff",
  "rx_bytes": 12345678,
  "tx_bytes": 23456789,
  "rx_errors": 0,
  "tx_errors": 0,
  "classification": "healthy"
}
```

Append to:

```text
/var/log/netwatch-pi/netwatch-pi.jsonl
```

---

## Health Checks

### 1. Interface Detection

Prefer the configured interface:

```bash
wlan0
```

If unavailable, detect default route interface:

```bash
ip route show default
```

Capture:

```bash
ip addr show
ip route show
```

### 2. Wi-Fi Association

Use:

```bash
iw dev wlan0 link
```

If unavailable, try:

```bash
iwconfig wlan0
```

Capture:

- SSID
- BSSID
- signal strength
- tx bitrate
- connected/disconnected state

### 3. Gateway Ping

```bash
ping -c 2 -W 2 <gateway-ip>
```

If gateway ping fails, Wi-Fi/LAN/eero may be affected.

### 4. Internet IP Ping

```bash
ping -c 2 -W 2 1.1.1.1
ping -c 2 -W 2 8.8.8.8
```

If gateway works but public IP fails, suspect eero/WAN/Comcast.

### 5. DNS Resolution

Use `dig` if available:

```bash
dig +time=2 +tries=1 google.com
dig +time=2 +tries=1 cloudflare.com
```

Fallback to:

```bash
getent hosts google.com
```

If public IP ping works but DNS fails, classify as DNS-only issue.

### 6. Windows Desktop Cross-Ping

If configured:

```bash
ping -c 2 -W 2 <windows-desktop-ip>
```

This tells whether the Pi can still reach the desktop during or near an event.

### 7. Gateway ARP / Neighbor Entry

Capture:

```bash
ip neigh show
ip neigh show <gateway-ip>
arp -an
```

If the gateway MAC changes, flag possible ARP conflict, duplicate gateway, or topology instability.

### 8. Interface Counters

Read:

```bash
cat /sys/class/net/wlan0/statistics/rx_bytes
cat /sys/class/net/wlan0/statistics/tx_bytes
cat /sys/class/net/wlan0/statistics/rx_packets
cat /sys/class/net/wlan0/statistics/tx_packets
cat /sys/class/net/wlan0/statistics/rx_errors
cat /sys/class/net/wlan0/statistics/tx_errors
cat /sys/class/net/wlan0/statistics/rx_dropped
cat /sys/class/net/wlan0/statistics/tx_dropped
```

---

## Failure Detection

A poll is degraded if:

- Wi-Fi is not associated.
- No local IPv4.
- No default gateway.
- Gateway ping fails.
- Both public IP pings fail.
- DNS resolution fails while public IP ping works.
- Windows desktop ping changes from OK to failed.
- Gateway MAC changes unexpectedly.
- RX/TX errors or drops increase sharply.

Trigger an event snapshot after:

```text
failure_threshold_count consecutive degraded samples
```

Default: 3.

Use event cooldown:

```text
event_cooldown_seconds = 300
```

Default: 300 seconds.

---

## Important Trigger Behavior

The Pi may not know the Windows desktop is broken unless it pings the desktop.

So if `windows_desktop_ip` is configured:

- A Windows ping failure should create a lower-severity event snapshot.
- The event classification can be `windows_unreachable_from_pi`.
- This may happen if the desktop is offline, asleep, or blocking ICMP, so do not overstate the diagnosis.
- If Windows ping fails but gateway/internet/DNS are healthy, this strongly suggests the outage is isolated to the desktop or wired path.

---

## Event Classification

Use:

```text
wifi_disconnected:
  wlan interface is not associated.

no_ipv4:
  Wi-Fi is associated but no IPv4 address exists.

gateway_unreachable:
  Wi-Fi and IPv4 exist but default gateway ping fails.

wan_unreachable:
  Gateway ping works but public IP pings fail.

dns_only_failure:
  Gateway and public IP pings work but DNS resolution fails.

windows_unreachable_from_pi:
  Pi network is healthy but Windows desktop ping fails.

possible_arp_conflict:
  Gateway MAC changes or duplicate gateway entries are observed.

possible_broadcast_storm:
  tcpdump/counter heuristics show unusually high ARP/broadcast/multicast traffic.

healthy:
  All checks pass.
```

---

## Event Snapshot Folder

On trigger, create:

```text
/var/log/netwatch-pi/events/YYYY-MM-DD_HH-mm-ss_pi_<classification>/
```

Write:

```text
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
```

---

## Commands to Capture

### Basic Network State

```bash
ip addr
ip route
ip neigh
arp -an
cat /etc/resolv.conf
```

### Wi-Fi State

```bash
iw dev wlan0 link
iwconfig wlan0
nmcli dev status
nmcli dev show wlan0
```

Each of these may fail depending on system setup. Log failures but do not crash.

### Service Logs

Capture recent network logs:

```bash
journalctl --since "10 minutes ago" --no-pager
journalctl -u NetworkManager --since "10 minutes ago" --no-pager
journalctl -u systemd-networkd --since "10 minutes ago" --no-pager
journalctl -u wpa_supplicant --since "10 minutes ago" --no-pager
```

Some units may not exist. Log command errors.

### Interface Statistics

Read all files under:

```text
/sys/class/net/wlan0/statistics/
```

Save as JSON.

---

## Packet Capture

On event trigger, run a short capture.

Preferred:

```bash
sudo timeout 60 tcpdump -i wlan0 -nn -e -s 0 -w tcpdump_capture.pcap \
  '(arp or icmp or port 53 or port 67 or port 68 or port 5353 or port 5355 or port 1900 or broadcast or multicast)'
```

Also write a text summary:

```bash
sudo timeout 15 tcpdump -i wlan0 -nn -e -c 300 \
  '(arp or icmp or port 53 or port 67 or port 68 or port 5353 or port 5355 or port 1900 or broadcast or multicast)'
```

Save to:

```text
tcpdump_summary.txt
```

Important protocols:

- ARP
- ICMP
- DNS `udp/53`
- DHCP `udp/67, udp/68`
- mDNS `udp/5353`
- LLMNR `udp/5355`
- SSDP/UPnP `udp/1900`
- broadcast
- multicast

Note: A Wi-Fi Pi may not see every wired Ethernet frame. It is still useful for determining if the eero/Wi-Fi side remains healthy.

---

## Optional Packet Parsing

If Python packet parsing dependencies are available, parse the capture for:

- Total packets.
- Broadcast frames.
- Multicast frames.
- ARP count.
- DHCP count.
- DNS count.
- mDNS count.
- SSDP count.
- Top source MACs.
- Top source IPs.
- Top destination IPs.
- Any repeated source MAC associated with the Windows desktop.

Do not require this for v1.

---

## CLI

Support:

```text
python netwatch_pi.py run
python netwatch_pi.py snapshot
python netwatch_pi.py classify-latest
python netwatch_pi.py install-service
python netwatch_pi.py uninstall-service
```

### `run`

Continuous watchdog.

### `snapshot`

Immediately creates a snapshot even if healthy.

### `classify-latest`

Reads latest event folder and prints diagnosis.

### `install-service`

Writes and enables a systemd unit.

### `uninstall-service`

Disables/removes the systemd unit.

---

## systemd Service

Create:

```text
/etc/systemd/system/netwatch-pi.service
```

Example:

```ini
[Unit]
Description=Network Watchdog for Raspberry Pi Wi-Fi Vantage Point
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/netwatch-pi/netwatch_pi.py run --config /etc/netwatch-pi/config.json
Restart=always
RestartSec=5
User=root
Group=root

[Install]
WantedBy=multi-user.target
```

Install steps:

```bash
sudo mkdir -p /opt/netwatch-pi
sudo mkdir -p /etc/netwatch-pi
sudo mkdir -p /var/log/netwatch-pi
sudo cp netwatch_pi.py /opt/netwatch-pi/
sudo cp config.json /etc/netwatch-pi/config.json
sudo cp netwatch-pi.service /etc/systemd/system/netwatch-pi.service
sudo systemctl daemon-reload
sudo systemctl enable --now netwatch-pi.service
sudo systemctl status netwatch-pi.service
```

View logs:

```bash
journalctl -u netwatch-pi -f
```

---

## Expected `summary.json`

Example:

```json
{
  "event_id": "2026-06-07_22-41-03_pi_windows_unreachable_from_pi",
  "host_label": "raspberry-pi-wifi",
  "classification": "windows_unreachable_from_pi",
  "plain_english": "The Raspberry Pi remained connected to Wi-Fi and could reach the gateway, internet IPs, and DNS, but could not ping the Windows desktop. This suggests the outage was isolated to the desktop, its Ethernet NIC, its wired path, or its local firewall/sleep state rather than a whole-network outage.",
  "local_ip": "192.168.4.25",
  "gateway_ip": "192.168.4.1",
  "gateway_mac_before": "aa:bb:cc:dd:ee:ff",
  "gateway_mac_after": "aa:bb:cc:dd:ee:ff",
  "windows_desktop_ip": "192.168.4.50",
  "gateway_ping_ok": true,
  "internet_ip_ping_ok": true,
  "dns_resolution_ok": true,
  "windows_ping_ok": false,
  "wifi_signal_dbm": -52,
  "suspicious_findings": [
    "Pi network remained healthy",
    "Windows desktop became unreachable from Wi-Fi vantage point"
  ],
  "recommended_next_steps": [
    "Compare timestamp with Windows event folder",
    "Test Windows desktop with USB Ethernet adapter",
    "Disable Windows Energy Efficient Ethernet and virtual bridge adapters",
    "Check managed switch counters if available"
  ]
}
```

---

## README Interpretation Guide

Include this in the generated project's README:

```text
How to interpret paired Windows + Raspberry Pi results:

1. Pi is healthy, Windows reports gateway_unreachable:
   Most likely Windows desktop NIC, NIC driver, Windows network stack, virtual adapter, or wired path issue.

2. Pi is healthy, Windows cannot ping Pi:
   Strongly suggests the failure is isolated to Windows desktop or wired side.

3. Pi and Windows both cannot ping gateway:
   Most likely LAN-wide eero/switch/topology/broadcast storm issue.

4. Pi and Windows both can ping gateway but not public IPs:
   Most likely eero WAN / Comcast issue.

5. Pi and Windows both can ping public IPs but DNS fails:
   DNS issue.

6. Pi sees high ARP/DHCP/mDNS/SSDP/broadcast/multicast traffic:
   Possible noisy device or storm. Compare source MACs with the Windows desktop MAC.

7. Gateway MAC changes around the event:
   Possible ARP conflict, duplicate IP, gateway confusion, or topology instability.

8. Pi loses Wi-Fi association:
   Wi-Fi/eero mesh side issue, not necessarily desktop-specific.
```

---

## Acceptance Criteria

The generated app is successful when:

- It runs as a systemd service.
- It writes JSONL samples every poll.
- It creates event folders after degraded network state.
- It captures Linux/Wi-Fi diagnostics.
- It captures a short tcpdump when possible.
- It never requires internet access to log.
- It can ping the Windows desktop if configured.
- It writes a clear `summary.json`.
- Its timestamps can be compared with Windows event folders.

---

## Stretch Goals

- Expose a local HTTP status endpoint on the Pi.
- Compress old event folders.
- Provide `export-latest` command to ZIP latest event.
- Add optional Prometheus metrics.
- Add optional SQLite storage for samples.
- Add optional MAC vendor lookup from a local OUI file only.

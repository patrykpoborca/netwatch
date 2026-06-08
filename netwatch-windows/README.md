# netwatch-windows — Windows Ethernet Watchdog

A logging-first network diagnostic watchdog for a Windows 10/11 desktop on Ethernet.
It continuously observes Ethernet health, writes one JSON-Lines health sample per poll,
and — when the network degrades — captures a rich diagnostic snapshot (PowerShell/cmd
dumps, Windows event logs, and a short packet capture) into a timestamped event folder.

It is designed to be run alongside a **Raspberry Pi Wi-Fi watchdog** so the same outage
is captured from two vantage points (wired desktop vs. wireless Pi). See the
**Paired Windows + Raspberry Pi Interpretation Guide** below.

> **Default behavior is logging-only.** Repair actions (NIC bounce, `ipconfig /renew`,
> `/flushdns`) NEVER run unless you pass `--repair` **and** set `"repair_enabled": true`
> in `config.json`. No cloud dependencies. No internet required to log.

---

## Topology this tool was built for

```
Comcast modem → gateway eero → 24-port switch → wired network / wired eeros / Windows desktop
```

The outage has occurred across different rooms, wall ports, switch ports, and cables, so a
single bad cable/jack/port is unlikely. The leading suspects are the desktop NIC
driver/hardware, a Windows virtual/bridge/VPN adapter, a desktop-originated broadcast/
multicast/ARP storm, or an eero/switch interaction. This tool helps classify which.

---

## Requirements

- Windows 10 or Windows 11.
- Python 3.11+.
- **Run as Administrator** for full diagnostic capture (packet capture, some cmdlets,
  adapter bounce in repair mode).
- **No third-party packages are required.** v1 is stdlib-only (HTTP push uses `urllib`).
- Optional: `scapy` or `pyshark` for richer packet-capture parsing (see `requirements.txt`).

---

## Installation

1. Copy the `netwatch-windows/` folder to the desktop, e.g. `C:\NetworkWatch\`.
2. (Optional) Edit `config.json` — at minimum confirm `host_label`,
   `preferred_interface_alias`, and `raspberry_pi_ip`.
3. (Optional, only for packet parsing) `pip install -r requirements.txt` after uncommenting
   `scapy`/`pyshark`.

The app creates `output_dir` (default `C:\NetworkSnapshots`) and an `events\` subfolder on
first run.

---

## Running manually

Open an **elevated** PowerShell / Command Prompt (Run as Administrator):

```powershell
# Continuous watchdog (writes a JSONL sample every poll_interval_seconds)
python netwatch_windows.py run

# Take a one-off diagnostic snapshot right now, even if the network is healthy
python netwatch_windows.py snapshot

# Print the diagnosis from the most recent event folder
python netwatch_windows.py classify-latest

# Continuous watchdog WITH repair on event (requires repair_enabled: true in config)
python netwatch_windows.py run --repair
```

Use `--config path\to\config.json` to point at a non-default config.

### What gets written

- **`C:\NetworkSnapshots\netwatch-windows.jsonl`** — one health sample per line.
- **`C:\NetworkSnapshots\events\YYYY-MM-DD_HH-mm-ss_windows_<classification>\`** — a full
  snapshot folder per detected event, containing:

  ```
  summary.json                       recent_samples.jsonl
  ipconfig_all.txt                   route_print.txt
  arp_a.txt                          active_connections.txt
  get_net_adapter.txt                get_net_adapter_statistics.txt
  get_net_adapter_advanced_property.txt   get_net_ip_configuration.txt
  get_net_neighbor.txt               dns_client_server_address.txt
  dns_client_cache.txt               network_eventlog_system.txt
  network_eventlog_application.txt   pktmon_capture.pcapng (+ pktmon_raw.etl)
  command_errors.json                (plus net_route / bindings / bridge / profile dumps)
  ```

`summary.json` includes a `classification`, a `plain_english` explanation,
`suspicious_findings`, and `recommended_next_steps`.

---

## Install as a Windows Scheduled Task

To run automatically at startup:

```powershell
# As current user, highest privileges (recommended; paths are simplest)
python netwatch_windows.py install-task

# Or run as SYSTEM
python netwatch_windows.py install-task --system

# Remove it later
python netwatch_windows.py uninstall-task
```

`install-task` writes `install_task.ps1` next to the script and attempts to register the
task **NetworkWatchWindows**. If registration fails (not elevated), run the generated
`install_task.ps1` from an **Administrator** PowerShell. The task is configured to restart
on failure and start when available.

---

## Health checks performed every poll

1. **Active Ethernet adapter detection** — enumerates all adapters and explicitly flags
   suspicious virtual/bridge/VPN ones (Hyper-V vEthernet, Docker, WSL, VPN, TAP/TUN,
   Network Bridge, ICS, VMware/VirtualBox, Tailscale/WireGuard/ZeroTier, etc.).
2. **Link state + statistics** — Up/Down, LinkSpeed, MAC, rx/tx bytes, error & discard
   counters (for storm / driver-issue heuristics).
3. **Gateway ping** — `Test-Connection` to the default gateway (auto-detected or override).
4. **Internet IP ping** — pings the configured public IPs (default 1.1.1.1, 8.8.8.8).
5. **DNS resolution** — `Resolve-DnsName` for the configured names.
6. **Raspberry Pi cross-ping** — pings the Pi (skipped if `raspberry_pi_ip` is null).
7. **Gateway ARP/neighbor** — captures the gateway MAC (`Get-NetNeighbor`, `arp -a`
   fallback) to detect ARP/gateway conflicts.

### Classification (set in `summary.json`)

`link_down`, `no_ipv4`, `gateway_unreachable`, `wan_unreachable`, `dns_only_failure`,
`lan_partial_failure`, `possible_arp_conflict`, `possible_adapter_driver_issue`, `healthy`.

An event snapshot fires after **`failure_threshold_count`** consecutive degraded samples
(default 3) and at most once per **`event_cooldown_seconds`** (default 300) so a single
outage does not create hundreds of folders.

---

## Packet capture (and its size cost)

On event trigger, a short, **bounded** capture runs for `packet_capture_seconds`
(default 60):

- **Preferred: `pktmon`** with filters for DNS/DHCP (ports 53/67/68), producing
  `pktmon_capture.pcapng` (+ `pktmon_raw.etl`).
- **Fallback: `netsh trace`** → `netsh_trace.etl` if pktmon is unavailable.

**Typical size cost:** with the default DNS/DHCP filter, a 60-second capture on a normal
home link is usually **well under ~5–20 MB**. A *broad/unfiltered* capture during an
actual broadcast/multicast storm can grow much faster (tens of MB per minute or more) —
this is exactly why the capture window is short and bounded. Keep
`packet_capture_seconds` modest (30–60s) unless you are actively hunting a storm. Event
folders are also size-managed by the retention policy below.

If `scapy`/`pyshark` is installed, a `packet_summary.txt` (top MACs, broadcast/multicast/
ARP/DHCP/DNS/mDNS/SSDP/LLMNR/NetBIOS counts) is added automatically — optional, never
required.

---

## Log-management / retention (log-swell control)

Configured under the `log_management` section. Defaults chosen to keep disk usage bounded:

| Setting | Default | Meaning |
|---|---|---|
| `max_jsonl_mb` | **50** | Rotate `netwatch-windows.jsonl` when it exceeds this size. |
| `max_rotated_jsonl_files` | **5** | Keep at most this many rotated JSONL files; delete older. |
| `gzip_rotated_jsonl` | **true** | Gzip rotated JSONL files (`*.jsonl.<UTCstamp>.gz`). |
| `max_event_folders` | **50** | Soft cap; oldest folders over this are auto-zipped. |
| `max_event_age_days` | **30** | Delete event items older than this. |
| `auto_zip_event_folders` | **true** | Compress oldest event folders to `.zip` once over the soft cap. |
| `hard_cap_event_items` | **200** | Absolute cap (folders + zips); oldest beyond this are deleted so disk never grows unbounded. |
| `prune_interval_seconds` | **3600** | A retention pass runs at startup and every hour during `run`. |

**How it works:** JSONL rotates by size, compresses, and keeps only the newest N rotated
files. Event folders are pruned by **age** first, then the oldest folders over the soft cap
are **zipped** (preserving evidence at a fraction of the size), and finally anything beyond
the **hard cap** is deleted. All thresholds are configurable.

---

## Optional repair mode

Only when started with `--repair` **and** `"repair_enabled": true`:

1. A **before** snapshot is taken.
2. Repair runs: `ipconfig /flushdns`, `ipconfig /renew`, then disable/enable the adapter.
3. An **after** snapshot is taken (captures `local_ip_after` / `gateway_mac_after`).

Without the flag (or with `repair_enabled: false`) the app is strictly logging-only and
will refuse to repair.

---

## Pushing logs to the central Raspberry Pi collector (optional)

The Pi can act as the central log host. Enable best-effort push in `config.json`:

```json
"collector": {
  "enabled": true,
  "base_url": "http://192.168.4.25:8787",
  "auth_token": "your-shared-secret-or-null",
  "push_samples": true,
  "push_events": true,
  "timeout_seconds": 3,
  "sample_batch_size": 10,
  "max_push_event_mb": 5
}
```

Pushing is **best-effort and non-blocking**: a short timeout is used, all exceptions are
swallowed and recorded into `command_errors.json`, and failures never stall or crash
polling. With `"enabled": false` (the default) the app works fully offline.

### HTTP contract (must match the Pi side)

All bodies are JSON. When `auth_token` is set, requests include
`Authorization: Bearer <auth_token>`. Every body carries `host_label`.

- **`POST {base_url}/ingest/samples`**
  Body (batched): `{"host_label": "...", "samples": [ <sample>, ... ]}`
  (a single bare sample object is also acceptable on the Pi side). Each sample object
  itself also includes a `host_label` field.

- **`POST {base_url}/ingest/events`**
  Body:
  ```json
  {
    "host_label": "gaming-desktop",
    "event_id": "2026-06-07_22-41-03_windows_gateway_unreachable",
    "classification": "gateway_unreachable",
    "summary": { ... full summary.json ... },
    "manifest": ["summary.json", "arp_a.txt", "..."]
  }
  ```

- **`POST {base_url}/ingest/events?host_label=<label>&event_id=<id>`** *(optional)*
  Content-Type `application/zip` — the zipped event folder, sent to the **same**
  `/ingest/events` path (the Pi host dispatches on Content-Type), only when the zip is
  under `max_push_event_mb` (default 5 MB).

---

## Paired Windows + Raspberry Pi Interpretation Guide

Run both watchdogs, make sure both clocks are correct (`w32tm /query /status` on Windows,
`timedatectl status` on the Pi), and reserve static IPs for both in the eero app. Then,
during an outage, find event folders in the same time window:

- Windows: `C:\NetworkSnapshots\events\`
- Raspberry Pi: `/var/log/netwatch-pi/events/`

Compare `summary.json`, `recent_samples.jsonl`, packet-capture summaries, gateway MAC,
local IP, DNS server, and the ping/DNS results.

### Interpretation matrix

| Windows result | Pi result | Likely meaning |
|---|---|---|
| Cannot ping gateway | Can ping gateway + internet | **Desktop NIC / Windows driver / virtual adapter / wired path / switch port** |
| Cannot ping gateway | Also cannot ping gateway | **LAN-wide eero/switch issue, broadcast storm, topology loop, or gateway eero** |
| Pings gateway, not 1.1.1.1 | Same issue | **WAN / eero / Comcast** |
| Pings 1.1.1.1, DNS fails | Same issue | **DNS issue** (eero/upstream resolver) |
| Pings 1.1.1.1, DNS fails | Pi DNS works | **Windows DNS client / VPN / proxy issue** |
| Gateway MAC changes around outage | (either) | **Possible ARP conflict, duplicate IP, gateway confusion, or topology issue** |
| Desktop outbound packet rate spikes before outage | (either) | **Possible desktop-originated storm or noisy service** |
| Problem disappears with a **USB Ethernet adapter** | — | **Strong evidence for motherboard NIC driver/hardware** |
| Problem disappears in a **Linux live USB** | — | **Strong evidence for Windows driver/software/virtual adapter** |

### First questions during an outage

1. Is the Pi healthy? If yes, it is probably not Comcast or the whole eero network.
2. Can the Pi ping the desktop? If no (Pi otherwise healthy), the problem is likely isolated
   to the desktop / wired side.
3. Can Windows ping the gateway? If no, it is not a pure DNS problem.
4. Can Windows ping `1.1.1.1` but not resolve names? If yes, it is likely DNS-specific.
5. Did the gateway MAC change? If yes, investigate duplicate IPs / ARP conflicts / topology.
6. Did packet volume spike before the failure? If yes, suspect a storm / noisy service / loop.

### Practical follow-up tests (in order)

1. Disable NIC power features (Energy Efficient/Green Ethernet, "turn off to save power",
   Large Send Offload, Flow Control, Interrupt Moderation).
2. Disable Windows virtual networking (Hyper-V switches, Docker/WSL adapters, VPN, Network
   Bridge, ICS, vendor network "optimizer" utilities).
3. Try a USB 3.0 Gigabit Ethernet adapter (disable the motherboard NIC).
4. Boot an Ubuntu live USB and use Ethernet.
5. Bypass the 24-port switch (desktop directly to the gateway eero).
6. If storms/loops are suspected, use a managed switch with STP/loop protection, storm
   control, per-port counters, and port mirroring.

---

## Privacy

Nothing is uploaded automatically (collector push is opt-in and LAN-local). Captured data
may contain local IPs, MAC addresses, DNS queries, hostnames, and connection metadata.
Keep logs local unless intentionally sharing for troubleshooting, and review packet
captures before sharing publicly.

---

## Project layout

```
netwatch-windows/
├── netwatch_windows.py     # single CLI entrypoint
├── config.json             # sample/default config (spec schema + log_management + collector)
├── requirements.txt        # stdlib-only; optional scapy/pyshark marked optional
├── README.md
└── netwatch/               # implementation package
    ├── __init__.py
    ├── app.py              # run loop + CLI command handlers
    ├── config.py           # config load/merge + defaults
    ├── runner.py           # robust command execution + command_errors capture
    ├── checks.py           # the 7 health checks + adapter detection
    ├── sampler.py          # builds one health sample per poll
    ├── state.py            # degraded detection, classification, summary text
    ├── snapshot.py         # event-folder capture (dumps, event logs, packets, summary)
    ├── logstore.py         # JSONL rotation + event-folder retention (log-swell control)
    ├── collector.py        # optional best-effort push to the Pi collector
    ├── repair.py           # gated repair actions
    ├── scheduler.py        # scheduled-task install/uninstall (.ps1 generation)
    └── pktparse.py         # OPTIONAL scapy/pyshark capture parsing
```

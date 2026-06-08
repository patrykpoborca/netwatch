# netwatch-pi — Raspberry Pi Wi-Fi Network Watchdog + Log-Collection Host

`netwatch-pi` is an always-on Raspberry Pi watchdog that observes home-network
health from the **Wi-Fi side** and captures a rich diagnostic snapshot whenever
the network degrades (or whenever it can no longer reach a paired Windows
desktop). It is the Pi half of a paired Windows + Raspberry Pi outage-logging
setup.

It also runs a small **log-collection HTTP host** so all logs — the Pi's own
*and* a Windows desktop's pushed logs — can be retrieved from one place.

```text
Comcast modem → gateway eero → 24-port switch → wired network / wired eeros / Windows desktop
                                                  Raspberry Pi joins over Wi-Fi as a vantage point
```

* **Python 3.11+**, **standard library only** (no pip dependencies required).
* Designed to **degrade gracefully** — missing tools, absent journal units, no
  `nmcli`, no `tcpdump` permission, etc. are all handled and logged, never fatal.
* **Never requires the internet to log.**
* **SD-card aware** — JSONL rotation, event-folder retention, and incoming-log
  caps keep disk usage bounded.

---

## Contents

```text
netwatch-pi/
├── netwatch_pi.py            # single entrypoint (delegates to the package)
├── netwatch/                 # implementation package
│   ├── __init__.py
│   ├── cli.py                # argparse CLI + subcommand dispatch
│   ├── config.py             # config.json loading + defaults + deep-merge
│   ├── shellcmd.py           # safe external-command wrapper (never crashes)
│   ├── checks.py             # the 8 health checks + sample assembly
│   ├── classify.py           # classification + degraded detection + summaries
│   ├── watchdog.py           # continuous run loop + rolling state machine
│   ├── snapshot.py           # event-snapshot folder (all files) + summary.json
│   ├── pktparse.py           # OPTIONAL packet parsing (scapy, try/except import)
│   ├── logmgmt.py            # SD-card control: rotation + retention + caps
│   ├── collector.py          # stdlib HTTP log-collection host
│   └── service.py            # systemd unit generation + install/uninstall
├── config.json               # sample/default config
├── netwatch-pi.service       # systemd unit (per spec)
├── requirements.txt          # stdlib-first; optional deps marked optional
└── README.md
```

---

## Install

### 1. System packages (apt)

The diagnostics rely on standard Linux networking tools. `nmcli` /
NetworkManager is optional — the app works without it.

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip \
    iproute2 dnsutils tcpdump wireless-tools iw network-manager
```

| Tool | Provides | Required? |
|---|---|---|
| `iproute2` (`ip`) | interface/route/neighbor state | strongly recommended |
| `dnsutils` (`dig`) | DNS resolution checks | optional (falls back to `getent`) |
| `tcpdump` | packet capture on event | optional (graceful if absent/no root) |
| `wireless-tools` (`iwconfig`) | Wi-Fi fallback | optional |
| `iw` | Wi-Fi association (preferred) | recommended |
| `network-manager` (`nmcli`) | extra Wi-Fi/device state | optional |

### 2. Install files (per the spec)

```bash
sudo mkdir -p /opt/netwatch-pi
sudo mkdir -p /etc/netwatch-pi
sudo mkdir -p /var/log/netwatch-pi
sudo cp -r netwatch_pi.py netwatch /opt/netwatch-pi/
sudo cp config.json /etc/netwatch-pi/config.json
sudo cp netwatch-pi.service /etc/systemd/system/netwatch-pi.service
```

Edit `/etc/netwatch-pi/config.json` and set at least:

* `windows_desktop_ip` — your desktop's reserved IP (or `null` to skip the
  cross-ping), and
* `preferred_interface` — usually `wlan0`.

### 3. Enable the systemd service

You can either copy the unit manually (above) or let the app write it:

```bash
# Option A: app writes + enables the unit (and runs daemon-reload / enable --now)
sudo python3 /opt/netwatch-pi/netwatch_pi.py \
    --config /etc/netwatch-pi/config.json install-service \
    --script-path /opt/netwatch-pi/netwatch_pi.py

# Option B: manual
sudo systemctl daemon-reload
sudo systemctl enable --now netwatch-pi.service
sudo systemctl status netwatch-pi.service
```

The default unit's `ExecStart` runs the watchdog **and** the collector host
together:

```ini
ExecStart=/usr/bin/python3 /opt/netwatch-pi/netwatch_pi.py run --serve --config /etc/netwatch-pi/config.json
```

If you do not want the HTTP collector exposed, install with `--no-serve` (or
remove `--serve` from the unit), or set `"collector": {"enabled": false}` in the
config.

### 4. View logs

```bash
journalctl -u netwatch-pi -f
tail -f /var/log/netwatch-pi/netwatch-pi.jsonl
```

### Uninstall

```bash
sudo python3 /opt/netwatch-pi/netwatch_pi.py uninstall-service
```

---

## Time synchronization (important)

The paired Windows + Pi logs are only useful if their timestamps line up. Make
sure NTP is healthy on both machines:

```bash
timedatectl status        # Raspberry Pi
```
```powershell
w32tm /query /status      # Windows
```

`netwatch-pi` writes timestamps in local time **with a timezone offset**
(e.g. `2026-06-07T22:41:03.123-05:00`) so they can be compared directly with the
Windows event folders.

---

## CLI

```text
python3 netwatch_pi.py [--config PATH] <command>

run [--serve]        Continuous watchdog. With --serve, also start the HTTP
                     log-collection host in a background thread.
snapshot             Immediately create an event snapshot, even if healthy.
classify-latest      Read the latest event folder and print its diagnosis.
install-service      Write + enable the systemd unit.
uninstall-service    Disable + remove the systemd unit.
serve                Run ONLY the HTTP log-collection host (blocking).
```

`--config` defaults to `/etc/netwatch-pi/config.json`. A missing or invalid
config degrades gracefully to built-in defaults.

---

## Configuration (`config.json`)

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
  "enable_tcpdump_capture": true,

  "log_management": {
    "max_jsonl_mb": 50,
    "max_rotated_jsonl_files": 5,
    "max_event_folders": 50,
    "max_event_age_days": 30,
    "prune_interval_seconds": 3600
  },

  "collector": {
    "enabled": true,
    "bind_host": "0.0.0.0",
    "bind_port": 8787,
    "auth_token": null,
    "incoming_dir": "/var/log/netwatch-pi/incoming",
    "max_incoming_mb": 500
  }
}
```

* If `gateway_ip_override` is `null`, the gateway is detected via
  `ip route show default`.
* If `windows_desktop_ip` is `null`, the Windows cross-ping is skipped.

---

## How it works

Every `poll_interval_seconds`, the watchdog runs all 8 health checks and appends
one JSONL sample to `netwatch-pi.jsonl`:

1. **Interface detection** — prefer `preferred_interface`, else the default-route
   interface (`ip route show default`); reads `ip addr` for the local IPv4.
2. **Wi-Fi association** — `iw dev <iface> link` (preferred), falling back to
   `iwconfig` for SSID/BSSID/signal/bitrate.
3. **Gateway ping** — `ping -c 2 -W 2 <gateway>`.
4. **Internet ping** — `ping` of each `internet_ips` entry (any success = OK).
5. **DNS resolution** — `dig +time=2 +tries=1 +short`, falling back to
   `getent hosts`.
6. **Windows desktop cross-ping** — `ping` of `windows_desktop_ip` if set.
7. **Gateway ARP/neighbor** — `ip neigh show <gateway>` for the gateway MAC.
8. **Interface counters** — reads `/sys/class/net/<iface>/statistics/*`.

A sample is **degraded** if any of: Wi-Fi not associated, no IPv4, no gateway,
gateway ping fails, both public IP pings fail, DNS fails while internet works,
Windows ping flips OK→failed, the gateway MAC changes, or error/drop counters
spike. After `failure_threshold_count` consecutive degraded samples (default 3),
and respecting `event_cooldown_seconds` (default 300s), an **event snapshot** is
created.

### Event classification

| Classification | Meaning |
|---|---|
| `wifi_disconnected` | wlan interface not associated |
| `no_ipv4` | associated but no IPv4 |
| `gateway_unreachable` | have IPv4 but gateway ping fails |
| `wan_unreachable` | gateway OK but both public IP pings fail |
| `dns_only_failure` | gateway + public OK but DNS fails |
| `windows_unreachable_from_pi` | Pi healthy but Windows ping fails (lower severity) |
| `possible_arp_conflict` | gateway MAC changed / duplicate gateway |
| `possible_broadcast_storm` | error/drop counters (or tcpdump) show a storm |
| `healthy` | all checks pass |

> **Important — Windows trigger behavior:** if the Pi is otherwise healthy but
> cannot ping the Windows desktop, the event is classified
> `windows_unreachable_from_pi` at *lower severity*. The desktop may simply be
> offline, asleep, or blocking ICMP, so this is **not** an overstated diagnosis
> on its own — always compare with the Windows event folder.

### Event snapshot folder

Created under `/var/log/netwatch-pi/events/YYYY-MM-DD_HH-mm-ss_pi_<classification>/`,
containing every file listed in the spec:

```text
summary.json              recent_samples.jsonl     ip_addr.txt
ip_route.txt              ip_neigh.txt             arp_an.txt
resolv_conf.txt           nmcli_dev_status.txt     iw_link.txt
iwconfig.txt              interface_statistics.json
journal_network_recent.txt journal_system_recent.txt
tcpdump_capture.pcap      tcpdump_summary.txt      command_errors.json
```

Any command that fails (missing tool, absent journal unit, no `nmcli`, no
tcpdump permission) writes an explanatory note into its file and an entry into
`command_errors.json`. The snapshot folder is **always complete**.

`summary.json` is human-readable and includes `plain_english`,
`suspicious_findings`, and `recommended_next_steps` tailored to the
classification.

---

## Packet capture & typical size cost

On an event, `netwatch-pi` runs a **bounded** capture (default
`packet_capture_seconds = 60`) filtered to the interesting protocols:

```text
arp, icmp, DNS/53, DHCP/67-68, mDNS/5353, LLMNR/5355, SSDP/1900, broadcast, multicast
```

plus a short text summary (`tcpdump -c 300`, ≤15s) in `tcpdump_summary.txt`.

**Typical size cost:** the BPF filter keeps captures small — on a quiet home LAN
a 60s capture is usually **well under ~1 MB** (often tens to low-hundreds of KB).
A noisy LAN / storm could produce a few MB. To bound it further, reduce
`packet_capture_seconds`, or set `enable_tcpdump_capture: false`. tcpdump needs
root (the service runs as root); if it cannot run, an empty
`tcpdump_capture.pcap` placeholder is written and the reason is recorded in
`command_errors.json`.

> A Wi-Fi Pi will not see every wired Ethernet frame. The capture is still
> useful for confirming whether the eero/Wi-Fi side stays healthy and for
> spotting ARP/broadcast/multicast storms.

### Optional Python packet parsing

If `scapy` is installed (see `requirements.txt`), `netwatch/pktparse.py` can
summarize a pcap (total/broadcast/multicast/ARP/DHCP/DNS/mDNS/SSDP counts, top
source MACs/IPs, and repeats of the Windows desktop MAC). This is **optional**
and not required for v1 — the import is wrapped in `try/except`.

---

## SD-card / log-swell control

The Pi runs off an SD card, so disk growth and write amplification are bounded.
All thresholds live in the `log_management` config section.

| Setting | Default | Effect |
|---|---|---|
| `max_jsonl_mb` | `50` | When `netwatch-pi.jsonl` exceeds this, it is gzip-rotated to a timestamped `.gz`. |
| `max_rotated_jsonl_files` | `5` | Keep at most this many `.gz` rotations; older are deleted. |
| `max_event_folders` | `50` | Cap on unzipped event folders; oldest are zipped beyond the cap; a hard cap of `2×` deletes the oldest zips so the card can't fill. |
| `max_event_age_days` | `30` | Event folders older than this are zipped (evidence kept, compressed). |
| `prune_interval_seconds` | `3600` | How often `run` performs a retention pass (also runs once at startup). |
| `collector.max_incoming_mb` | `500` | Hard cap on the size of pushed/incoming logs; oldest are pruned first. |

**Write-amplification notes:**

* JSONL is written **open-append-write-flush**: one append per sample, flushed
  to the OS buffer, with **no `fsync` per line**. This avoids rewriting the whole
  file and minimizes SD-card wear while staying durable within seconds.
* Rotation truncates the live file in place (keeps the inode stable).
* The retention/prune pass runs at startup and every `prune_interval_seconds`.

**Tip:** to eliminate SD-card writes entirely for the hot JSONL path, point
`output_dir` and `jsonl_log_path` at a tmpfs (RAM) or a USB drive, e.g.
`/run/netwatch-pi` (tmpfs, lost on reboot) or `/mnt/usb/netwatch-pi`. Event
snapshots and incoming logs can likewise be redirected by changing `output_dir`
and `collector.incoming_dir`.

---

## Collection host — HTTP API

The collector turns the Pi into a single place to retrieve all logs and to
receive the Windows desktop's pushed logs. It uses **only the Python standard
library** (`http.server` + `socketserver`, threaded). Default bind:
`0.0.0.0:8787`.

Start it:

```bash
python3 netwatch_pi.py serve                 # collector only (blocking)
python3 netwatch_pi.py run --serve           # watchdog + collector (thread)
```

### Authentication

If `collector.auth_token` is set, **every** endpoint requires:

```text
Authorization: Bearer <token>
```

and returns `401` otherwise. If `auth_token` is `null` (default), the server is
**open** and assumes a **trusted LAN**. Only run open on a network you control.

### Safety

* The server runs in its own thread and **cannot crash the watchdog**.
* Bad requests return proper `4xx`; request bodies are size-limited
  (JSON ingest ≤ 8 MB, zip upload ≤ 64 MB).
* `host_label` and `event_id` are **sanitized** to a single safe path segment —
  no path traversal is possible.
* The same retention/caps applied to the Pi's own logs are applied to
  `incoming_dir` (pushed-sample rotation + `max_incoming_mb` size cap).

### READ endpoints (retrieve all logs from one place)

| Method | Path | Response |
|---|---|---|
| `GET` | `/health` | `{"status":"ok","service":"netwatch-pi-collector","host_label":...,"time":...,"auth_required":bool}` |
| `GET` | `/samples/latest?n=100` | `{"count":N,"samples":[ {sample}, ... ]}` — last `n` of the Pi's own JSONL samples (default 100, max 5000) |
| `GET` | `/events` | `{"count":N,"events":[{"id","classification","time","size_bytes","archived"}]}` |
| `GET` | `/events/{event_id}` | that event's `summary.json` (object) or `404` |
| `GET` | `/events/{event_id}/download` | `application/zip` of the event folder (streamed) or `404` |
| `GET` | `/collected` | `{"count":N,"hosts":[{"host_label","samples_file_exists","samples_size_bytes","events":[{"id","time","size_bytes"}]}]}` |

### INGEST endpoints (Windows desktop pushes its logs to the Pi)

This is the **exact contract** the Windows app's push client must follow.

#### `POST /ingest/samples`

* `Content-Type: application/json`
* Body is **either** a single sample object **or** `{"samples": [ {...}, ... ]}`.
  (A bare JSON array is also accepted.)
* Each sample's `host_label` selects the destination; missing → `"unknown-host"`.
* Stored (appended) to `incoming_dir/<host_label>/samples.jsonl` (rotated per the
  same `log_management` rules).
* Response: `{"status":"ok","written":N}`.

```jsonc
// single
{ "host_label": "windows-desktop", "timestamp": "2026-06-07T22:41:03-05:00",
  "classification": "gateway_unreachable", "gateway_ping_ok": false }

// batch
{ "samples": [ { "host_label": "windows-desktop", "classification": "healthy" },
               { "host_label": "windows-desktop", "classification": "wan_unreachable" } ] }
```

#### `POST /ingest/events`

Two accepted forms:

**(a) JSON summary** — `Content-Type: application/json`:

```jsonc
{ "host_label": "windows-desktop",
  "event_id": "2026-06-07_22-41-03_win_gateway_unreachable",
  "classification": "gateway_unreachable",
  "summary": { /* full summary.json object */ } }
```

Stored to `incoming_dir/<host_label>/events/<event_id>/summary.json`.
`host_label` and `event_id` are **required** (event_id sanitized).
Response: `{"status":"ok","host_label":...,"event_id":...}`.

**(b) Zipped event upload** — `Content-Type: application/zip` (or
`application/octet-stream`), with query parameters:

```text
POST /ingest/events?host_label=windows-desktop&event_id=2026-06-07_22-41-03_win_gateway_unreachable
Content-Type: application/zip
<binary zip body>
```

The zip is validated and stored as
`incoming_dir/<host_label>/events/<event_id>/event.zip`, enforcing
`max_incoming_mb` (and a per-request 64 MB cap). Response same as (a).

### curl examples

**Pull all of the Pi's logs from one place:**

```bash
PI=http://raspberry-pi.local:8787
# (add  -H "Authorization: Bearer $TOKEN"  to each call if auth_token is set)

curl -s $PI/health
curl -s "$PI/samples/latest?n=200"
curl -s $PI/events
curl -s $PI/events/2026-06-07_22-41-03_pi_windows_unreachable_from_pi
curl -s $PI/events/2026-06-07_22-41-03_pi_windows_unreachable_from_pi/download -o pi_event.zip
curl -s $PI/collected           # logs the Windows desktop pushed to the Pi
```

**Windows desktop pushing its logs to the Pi:**

```bash
PI=http://raspberry-pi.local:8787
# push a batch of samples
curl -s -X POST $PI/ingest/samples \
  -H 'Content-Type: application/json' \
  -d '{"samples":[{"host_label":"windows-desktop","classification":"gateway_unreachable","gateway_ping_ok":false}]}'

# push an event summary
curl -s -X POST $PI/ingest/events \
  -H 'Content-Type: application/json' \
  -d '{"host_label":"windows-desktop","event_id":"2026-06-07_22-41-03_win_gateway_unreachable","classification":"gateway_unreachable","summary":{"classification":"gateway_unreachable","plain_english":"Windows could not reach the gateway over Ethernet."}}'

# push a zipped event folder
curl -s -X POST "$PI/ingest/events?host_label=windows-desktop&event_id=2026-06-07_22-41-03_win_gateway_unreachable" \
  -H 'Content-Type: application/zip' \
  --data-binary @win_event.zip
```

With auth enabled, add `-H "Authorization: Bearer YOUR_TOKEN"` to every request.

---

## Interpreting paired Windows + Raspberry Pi results

```text
1. Pi is healthy, Windows reports gateway_unreachable:
   Most likely Windows desktop NIC, NIC driver, Windows network stack,
   virtual adapter, or wired path issue.

2. Pi is healthy, Windows cannot ping Pi:
   Strongly suggests the failure is isolated to the Windows desktop or wired side.

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

The most useful first questions during an outage: Is the Pi healthy? Can the Pi
ping the desktop? Can Windows ping the gateway? Can Windows ping `1.1.1.1` but
not resolve names? Did the gateway MAC change? Did packet volume spike?

### Static DHCP reservations

In the eero app, reserve IPs (using your actual range), e.g.:

```text
Windows desktop: 192.168.4.50   ->  set Pi config "windows_desktop_ip"
Raspberry Pi:    192.168.4.25   ->  set Windows app "raspberry_pi_ip"
```

so the two devices can cross-ping each other.

---

## Privacy note

> The tools should **not upload anything automatically**. Captured data
> (samples, snapshots, packet captures) may include local IP addresses, MAC
> addresses, DNS queries, hostnames, device names, local service-discovery
> traffic, and connection metadata.
>
> Keep logs local unless intentionally sharing for troubleshooting. The
> collection host's `incoming_dir` likewise holds another machine's network
> metadata. If you expose the collector beyond a trusted LAN, set
> `collector.auth_token`. Before sending packet captures to anyone, review them
> for privacy.

---

## Development notes

This is Linux-specific code. It was authored on macOS and cannot be run
end-to-end there (no `wlan0`, no `tcpdump` permission, etc.), but it is written
to degrade gracefully on any platform. To smoke-check locally:

```bash
python3 -m py_compile netwatch_pi.py netwatch/*.py
python3 netwatch_pi.py --config ./config.json snapshot   # produces a full event folder
python3 netwatch_pi.py --config ./config.json serve      # starts the collector
```

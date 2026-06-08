# Home Network Diagnostics

Paired network-outage watchdogs for diagnosing intermittent Ethernet drops on a
Windows desktop, observed from two vantage points at once.

```text
Comcast modem → gateway eero → 24-port switch → wired network / wired eeros / Windows desktop
                            (Wi-Fi) ↳ Raspberry Pi  (Wi-Fi vantage point + log host)
```

## Layout

| Path | What it is |
|---|---|
| [`netwatch-windows/`](netwatch-windows/) | Windows Ethernet watchdog (Python + PowerShell). Runs on the desktop. |
| [`netwatch-pi/`](netwatch-pi/) | Raspberry Pi Wi-Fi watchdog **and central log-collection host** (Python). Always-on. |
| [`windows_ethernet_watchdog_spec.md`](windows_ethernet_watchdog_spec.md) | Spec for the Windows app. |
| [`raspberry_pi_wifi_watchdog_spec.md`](raspberry_pi_wifi_watchdog_spec.md) | Spec for the Pi app. |
| [`paired_network_outage_runbook.md`](paired_network_outage_runbook.md) | How to read both sides together during an outage. |

Each subproject has its own README with full install/run/retention details.

## How the two machines get the code

Both machines pull this repo with plain `git`. Clone once, then `git pull` to update.

### Raspberry Pi (always-on host)

```bash
sudo apt update
sudo apt install -y git python3 python3-venv python3-pip iproute2 dnsutils tcpdump wireless-tools iw network-manager
git clone <REPO_URL> ~/network-diagnostics
cd ~/network-diagnostics/netwatch-pi
# follow netwatch-pi/README.md to configure /etc/netwatch-pi/config.json and install the systemd service
```

To update later:

```bash
cd ~/network-diagnostics && git pull
sudo systemctl restart netwatch-pi   # if installed as a service
```

### Windows desktop

```powershell
# install Git for Windows and Python 3.11+ first
git clone <REPO_URL> C:\NetworkWatch
cd C:\NetworkWatch\netwatch-windows
# follow netwatch-windows\README.md to configure config.json and (optionally) install the scheduled task
```

To update later:

```powershell
cd C:\NetworkWatch; git pull
```

## Centralized logs

The Pi runs an HTTP collection host (default `:8787`). The Windows app can optionally
**push** its samples/events to the Pi so all logs are retrievable from one place, and
the Pi exposes read endpoints (`/samples/latest`, `/events`, `/collected`, …). See
[`netwatch-pi/README.md`](netwatch-pi/README.md) for the full API and
[`netwatch-windows/README.md`](netwatch-windows/README.md) for enabling the push client.

## Privacy

Captured data (packet traces, event folders, JSONL samples) contains local IPs, MAC
addresses, DNS queries, and hostnames. **These are git-ignored and must not be committed.**
Only the application code lives in this repo. See the runbook's privacy notes before
sharing any captured evidence.

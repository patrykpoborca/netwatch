"""systemd unit generation + install/uninstall (exactly per the spec).

``install-service`` writes the unit to /etc/systemd/system/netwatch-pi.service,
runs ``systemctl daemon-reload`` and ``systemctl enable --now``.
``uninstall-service`` disables and removes it.

All systemctl calls are wrapped so partial environments (no systemd, not root)
produce a clear message instead of a traceback.
"""

from __future__ import annotations

import os

from .shellcmd import have_tool, run_command

SERVICE_PATH = "/etc/systemd/system/netwatch-pi.service"
SERVICE_NAME = "netwatch-pi.service"

# The unit text. ExecStart honours the install location and config path. The
# default ExecStart runs the watchdog AND the collector together via --serve so
# the Pi is reachable as a log host out of the box; the README documents how to
# drop --serve if the collector is not wanted.
UNIT_TEMPLATE = """[Unit]
Description=Network Watchdog for Raspberry Pi Wi-Fi Vantage Point
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={python} {script} run --serve --config {config}
Restart=always
RestartSec=5
User=root
Group=root

[Install]
WantedBy=multi-user.target
"""


def render_unit(python: str, script: str, config: str) -> str:
    """Return the rendered systemd unit text."""
    return UNIT_TEMPLATE.format(python=python, script=script, config=config)


def install_service(script_path: str, config_path: str, serve: bool = True) -> int:
    """Write the unit, daemon-reload, and enable --now. Returns an exit code."""
    python = "/usr/bin/python3"
    if not os.path.exists(python):
        # Fall back to whatever python3 is on PATH.
        import shutil

        python = shutil.which("python3") or python

    unit = render_unit(python, os.path.abspath(script_path), config_path)
    if not serve:
        unit = unit.replace("run --serve --config", "run --config")

    try:
        with open(SERVICE_PATH, "w", encoding="utf-8") as fh:
            fh.write(unit)
    except PermissionError:
        print(f"Permission denied writing {SERVICE_PATH}. Re-run with sudo.")
        return 1
    except OSError as exc:
        print(f"Could not write {SERVICE_PATH}: {exc}")
        return 1

    print(f"Wrote {SERVICE_PATH}")

    if not have_tool("systemctl"):
        print("systemctl not found — unit written but not enabled (no systemd?).")
        return 0

    for args in (
        ["systemctl", "daemon-reload"],
        ["systemctl", "enable", "--now", SERVICE_NAME],
    ):
        res = run_command(args, timeout=30)
        if not res.ok:
            print(f"WARNING: '{' '.join(args)}' failed: {res.error}\n{res.stderr}")

    status = run_command(["systemctl", "status", SERVICE_NAME], timeout=30)
    print(status.stdout or status.stderr)
    print("Installed. View logs with: journalctl -u netwatch-pi -f")
    return 0


def uninstall_service() -> int:
    """Disable and remove the systemd unit. Returns an exit code."""
    if have_tool("systemctl"):
        for args in (
            ["systemctl", "disable", "--now", SERVICE_NAME],
            ["systemctl", "daemon-reload"],
        ):
            res = run_command(args, timeout=30)
            if not res.ok:
                print(f"WARNING: '{' '.join(args)}' failed: {res.error}")
    else:
        print("systemctl not found — skipping disable.")

    try:
        if os.path.exists(SERVICE_PATH):
            os.remove(SERVICE_PATH)
            print(f"Removed {SERVICE_PATH}")
        else:
            print(f"{SERVICE_PATH} not present.")
    except PermissionError:
        print(f"Permission denied removing {SERVICE_PATH}. Re-run with sudo.")
        return 1
    except OSError as exc:
        print(f"Could not remove {SERVICE_PATH}: {exc}")
        return 1

    if have_tool("systemctl"):
        run_command(["systemctl", "daemon-reload"], timeout=30)
    print("Uninstalled.")
    return 0

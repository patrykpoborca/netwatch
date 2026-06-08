"""Windows Scheduled Task install/uninstall helpers.

Generates the PowerShell shown in the spec (writing it to ``install_task.ps1`` /
``uninstall_task.ps1`` next to the project) and invokes it. Falls back gracefully if not
running on Windows / lacking privileges - it still writes the .ps1 so an operator can run
it manually elevated.
"""

from __future__ import annotations

import os
import sys
from typing import Optional

from .config import Config
from .runner import CommandErrorLog, run_powershell

TASK_NAME = "NetworkWatchWindows"


def _entrypoint_path() -> str:
    """Best-effort absolute path to netwatch_windows.py for the task action."""
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    candidate = os.path.join(here, "netwatch_windows.py")
    return candidate if os.path.isfile(candidate) else os.path.abspath("netwatch_windows.py")


def _install_script(entry: str, python_exe: str, run_as_system: bool) -> str:
    """Return the PowerShell that registers the scheduled task."""
    if run_as_system:
        principal = '$Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest'
    else:
        # Current user with highest privileges (spec's alternative).
        principal = (
            '$Principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\\$env:USERNAME" '
            "-LogonType Interactive -RunLevel Highest"
        )
    return (
        f'$Action = New-ScheduledTaskAction -Execute "{python_exe}" '
        f'-Argument "\\"{entry}\\" run"\n'
        "$Trigger = New-ScheduledTaskTrigger -AtStartup\n"
        f"{principal}\n"
        '$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries '
        "-DontStopIfGoingOnBatteries -StartWhenAvailable -RestartCount 999 "
        "-RestartInterval (New-TimeSpan -Minutes 1)\n"
        f'Register-ScheduledTask -TaskName "{TASK_NAME}" -Action $Action -Trigger $Trigger '
        "-Principal $Principal -Settings $Settings -Force\n"
    )


def _uninstall_script() -> str:
    return (
        f'Unregister-ScheduledTask -TaskName "{TASK_NAME}" -Confirm:$false '
        "-ErrorAction SilentlyContinue\n"
        f'Write-Output "Unregistered task {TASK_NAME} (if it existed)."\n'
    )


def install_task(cfg: Config, run_as_system: bool = False, error_log: Optional[CommandErrorLog] = None) -> str:
    """Write install_task.ps1 and register the scheduled task. Returns the script path."""
    if error_log is None:
        error_log = CommandErrorLog()
    entry = _entrypoint_path()
    python_exe = sys.executable or "python"
    script = _install_script(entry, python_exe, run_as_system)

    project_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    ps1 = os.path.join(project_dir, "install_task.ps1")
    with open(ps1, "w", encoding="utf-8") as fh:
        fh.write(script)

    # Try to register now (only meaningful on Windows + elevated).
    run_powershell(script, error_log=error_log, timeout=60, label="install scheduled task")
    return ps1


def uninstall_task(error_log: Optional[CommandErrorLog] = None) -> str:
    """Write uninstall_task.ps1 and unregister the scheduled task. Returns the script path."""
    if error_log is None:
        error_log = CommandErrorLog()
    script = _uninstall_script()
    project_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    ps1 = os.path.join(project_dir, "uninstall_task.ps1")
    with open(ps1, "w", encoding="utf-8") as fh:
        fh.write(script)
    run_powershell(script, error_log=error_log, timeout=60, label="uninstall scheduled task")
    return ps1

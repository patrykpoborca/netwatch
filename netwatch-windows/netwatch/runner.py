"""Robust external-command execution.

Everything the watchdog runs on Windows (PowerShell cmdlets, ``ipconfig``, ``arp``,
``pktmon``, ``netsh``...) goes through this module. The guiding rule from the spec:

    "Must degrade gracefully if any command is unavailable - capture errors into
     command_errors.json, never crash the loop. Wrap every external command call."

``CommandError`` accumulates failures so the caller can serialize them to
``command_errors.json`` in each event folder. ``run_*`` helpers NEVER raise on a
failed command; they return a structured :class:`CommandResult` instead.
"""

from __future__ import annotations

import subprocess
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence


@dataclass
class CommandResult:
    """Result of a single external command invocation (never raises)."""

    command: str
    returncode: Optional[int]
    stdout: str
    stderr: str
    ok: bool
    duration_seconds: float
    error: Optional[str] = None  # populated when the command could not be run at all


class CommandErrorLog:
    """Accumulates command failures for serialization into ``command_errors.json``."""

    def __init__(self) -> None:
        self.errors: List[Dict[str, object]] = []

    def record(self, result: CommandResult) -> None:
        """Record a failed/errored command. No-op for successful commands."""
        if result.ok:
            return
        self.errors.append(
            {
                "command": result.command,
                "returncode": result.returncode,
                "error": result.error,
                "stderr": (result.stderr or "")[:4000],
                "duration_seconds": round(result.duration_seconds, 3),
            }
        )

    def record_raw(self, command: str, message: str) -> None:
        """Record an arbitrary error message not tied to a CommandResult."""
        self.errors.append({"command": command, "error": message})

    def as_list(self) -> List[Dict[str, object]]:
        return list(self.errors)

    def __bool__(self) -> bool:
        return bool(self.errors)


def _run(
    args: Sequence[str],
    *,
    timeout: float,
    error_log: Optional[CommandErrorLog] = None,
    label: Optional[str] = None,
) -> CommandResult:
    """Execute ``args`` and return a :class:`CommandResult`. Never raises.

    Any exception (missing executable, timeout, permission error, etc.) is captured
    into the result's ``error`` field and, if provided, recorded in ``error_log``.
    """
    command_str = label or " ".join(args)
    start = time.monotonic()
    try:
        proc = subprocess.run(
            list(args),
            capture_output=True,
            text=True,
            timeout=timeout,
            # Decode leniently: Windows console output is frequently mojibake-prone.
            errors="replace",
        )
        duration = time.monotonic() - start
        result = CommandResult(
            command=command_str,
            returncode=proc.returncode,
            stdout=proc.stdout or "",
            stderr=proc.stderr or "",
            ok=(proc.returncode == 0),
            duration_seconds=duration,
        )
    except FileNotFoundError as exc:
        duration = time.monotonic() - start
        result = CommandResult(
            command=command_str,
            returncode=None,
            stdout="",
            stderr="",
            ok=False,
            duration_seconds=duration,
            error=f"executable not found: {exc}",
        )
    except subprocess.TimeoutExpired as exc:
        duration = time.monotonic() - start
        result = CommandResult(
            command=command_str,
            returncode=None,
            stdout=(exc.stdout or "") if isinstance(exc.stdout, str) else "",
            stderr=(exc.stderr or "") if isinstance(exc.stderr, str) else "",
            ok=False,
            duration_seconds=duration,
            error=f"timeout after {timeout}s",
        )
    except Exception as exc:  # noqa: BLE001 - intentional catch-all for robustness
        duration = time.monotonic() - start
        result = CommandResult(
            command=command_str,
            returncode=None,
            stdout="",
            stderr="",
            ok=False,
            duration_seconds=duration,
            error=f"{type(exc).__name__}: {exc}",
        )

    if error_log is not None:
        error_log.record(result)
    return result


def run_powershell(
    script: str,
    *,
    timeout: float = 30.0,
    error_log: Optional[CommandErrorLog] = None,
    label: Optional[str] = None,
) -> CommandResult:
    """Run a PowerShell snippet via ``powershell.exe -NoProfile -NonInteractive``.

    Uses ``-Command`` so multi-line scripts and cmdlets work uniformly. ``$ErrorAction
    Preference`` is left at default; callers append ``-ErrorAction SilentlyContinue``
    where the spec requires non-fatal behavior.
    """
    full = f"$ProgressPreference='SilentlyContinue'; {script}"
    args = [
        "powershell.exe",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        full,
    ]
    return _run(args, timeout=timeout, error_log=error_log, label=label or f"powershell: {script.strip()[:120]}")


def run_cmd(
    args: Sequence[str],
    *,
    timeout: float = 30.0,
    error_log: Optional[CommandErrorLog] = None,
    label: Optional[str] = None,
) -> CommandResult:
    """Run a plain executable (``ipconfig``, ``arp``, ``route``, ``netstat``, ...)."""
    return _run(args, timeout=timeout, error_log=error_log, label=label)

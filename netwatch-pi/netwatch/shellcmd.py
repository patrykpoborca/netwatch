"""Safe external-command execution.

EVERY shell/diagnostic command in netwatch-pi goes through :func:`run_command`.
It guarantees:
  * The watchdog loop never crashes because a tool is missing or errored
    (FileNotFoundError, timeouts, permission errors are all caught).
  * Errors are collected into a structured list so they can be written to
    ``command_errors.json`` in an event snapshot.

Nothing here requires the network — commands are local diagnostics.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence


@dataclass
class CommandResult:
    """Result of running one external command."""

    command: str
    returncode: Optional[int]
    stdout: str
    stderr: str
    ok: bool
    error: Optional[str] = None  # set when the command could not run at all


@dataclass
class CommandErrorCollector:
    """Accumulates command failures for ``command_errors.json``."""

    errors: List[Dict[str, object]] = field(default_factory=list)

    def record(self, result: CommandResult) -> None:
        if result.ok:
            return
        self.errors.append(
            {
                "command": result.command,
                "returncode": result.returncode,
                "error": result.error,
                "stderr": (result.stderr or "")[:2000],
            }
        )

    def as_list(self) -> List[Dict[str, object]]:
        return list(self.errors)


def have_tool(name: str) -> bool:
    """Return True if an executable named ``name`` is on PATH."""
    return shutil.which(name) is not None


def run_command(
    args: Sequence[str],
    timeout: float = 15.0,
    collector: Optional[CommandErrorCollector] = None,
    check_tool: bool = True,
) -> CommandResult:
    """Run ``args`` and return a :class:`CommandResult`, never raising.

    Parameters
    ----------
    args:
        Argument vector (list form — we never use ``shell=True``).
    timeout:
        Seconds before the command is killed.
    collector:
        Optional :class:`CommandErrorCollector` to record failures into.
    check_tool:
        If True, verify the first arg's executable exists before invoking, so we
        produce a clean "tool not installed" error instead of an exception.
    """
    cmd_str = " ".join(args)

    if check_tool and args and not have_tool(args[0]):
        result = CommandResult(
            command=cmd_str,
            returncode=None,
            stdout="",
            stderr="",
            ok=False,
            error=f"tool not found: {args[0]}",
        )
        if collector:
            collector.record(result)
        return result

    try:
        proc = subprocess.run(
            list(args),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        result = CommandResult(
            command=cmd_str,
            returncode=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
            ok=(proc.returncode == 0),
            error=None if proc.returncode == 0 else f"exit code {proc.returncode}",
        )
    except subprocess.TimeoutExpired:
        result = CommandResult(
            command=cmd_str,
            returncode=None,
            stdout="",
            stderr="",
            ok=False,
            error=f"timeout after {timeout}s",
        )
    except FileNotFoundError:
        result = CommandResult(
            command=cmd_str,
            returncode=None,
            stdout="",
            stderr="",
            ok=False,
            error=f"tool not found: {args[0] if args else '?'}",
        )
    except PermissionError as exc:
        result = CommandResult(
            command=cmd_str,
            returncode=None,
            stdout="",
            stderr="",
            ok=False,
            error=f"permission error: {exc}",
        )
    except OSError as exc:  # catch-all for exec failures
        result = CommandResult(
            command=cmd_str,
            returncode=None,
            stdout="",
            stderr="",
            ok=False,
            error=f"os error: {exc}",
        )

    if collector:
        collector.record(result)
    return result

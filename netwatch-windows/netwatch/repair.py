"""Optional repair mode (gated behind --repair AND repair_enabled).

NEVER runs unless both the ``--repair`` CLI flag is present and ``repair_enabled`` is true
in config. Per the spec, a snapshot is taken BEFORE and AFTER the repair actions so the
effect is captured for later analysis.

Repair actions (manually requested only):
    ipconfig /renew
    ipconfig /flushdns
    Disable-NetAdapter / Enable-NetAdapter (bounce the link)
"""

from __future__ import annotations

from typing import List, Optional

from .config import Config
from .runner import CommandErrorLog, run_cmd, run_powershell


def run_repair_actions(
    cfg: Config, alias: Optional[str], error_log: CommandErrorLog
) -> List[str]:
    """Execute the repair sequence. Returns a list of human-readable action results.

    The caller is responsible for taking before/after snapshots around this call and for
    verifying that both ``--repair`` and ``repair_enabled`` are set.
    """
    actions: List[str] = []

    r1 = run_cmd(["ipconfig", "/flushdns"], error_log=error_log, timeout=30, label="ipconfig /flushdns")
    actions.append(f"ipconfig /flushdns -> {'ok' if r1.ok else 'failed'}")

    r2 = run_cmd(["ipconfig", "/renew"], error_log=error_log, timeout=90, label="ipconfig /renew")
    actions.append(f"ipconfig /renew -> {'ok' if r2.ok else 'failed'}")

    if alias:
        bounce = (
            f"Disable-NetAdapter -Name '{alias}' -Confirm:$false -ErrorAction SilentlyContinue; "
            "Start-Sleep -Seconds 3; "
            f"Enable-NetAdapter -Name '{alias}' -Confirm:$false -ErrorAction SilentlyContinue"
        )
        r3 = run_powershell(bounce, error_log=error_log, timeout=60, label=f"bounce adapter {alias}")
        actions.append(f"disable/enable adapter '{alias}' -> {'ok' if r3.ok else 'failed'}")
    else:
        actions.append("adapter bounce skipped (no adapter alias resolved)")

    return actions

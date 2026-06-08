"""netwatch-windows: Windows Ethernet Watchdog.

A logging-first network diagnostic watchdog for Windows desktops. It continuously
observes Ethernet health, writes JSONL health samples, and captures rich diagnostic
snapshots (PowerShell/cmd dumps, event logs, packet captures) when a failure occurs.

Default behavior is logging-only. Repair actions are gated behind an explicit
``--repair`` flag and ``repair_enabled`` config. No cloud dependencies are required;
optional best-effort push to a central Raspberry Pi collector is supported.

See README.md for the full operator guide and the paired Windows+Pi interpretation
matrix.
"""

__version__ = "1.0.0"

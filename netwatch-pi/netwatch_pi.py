#!/usr/bin/env python3
"""netwatch-pi — single entrypoint.

This thin wrapper delegates to the :mod:`netwatch` package so the project can be
shipped as one file you invoke (``python3 netwatch_pi.py <command>``) while the
implementation stays cleanly split into modules.

Subcommands:
    run [--serve]      Continuous watchdog (optionally start the collector host)
    snapshot           Capture an event snapshot immediately
    classify-latest    Print the diagnosis from the latest event folder
    install-service    Write + enable the systemd unit
    uninstall-service  Disable + remove the systemd unit
    serve              Run only the HTTP log-collection host

The package directory (``netwatch/``) must sit next to this file, which is how
the spec's install steps copy it to /opt/netwatch-pi/.
"""

from __future__ import annotations

import os
import sys

# Ensure the directory containing this script is importable so ``netwatch`` is
# found regardless of the current working directory (e.g. under systemd).
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from netwatch.cli import main  # noqa: E402  (after sys.path tweak)


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""netwatch-windows entrypoint.

Single CLI entrypoint required by the spec. All logic lives in the ``netwatch`` package;
this file just wires up the package's ``main()`` so the documented commands work:

    python netwatch_windows.py run
    python netwatch_windows.py snapshot
    python netwatch_windows.py classify-latest
    python netwatch_windows.py install-task
    python netwatch_windows.py uninstall-task
    python netwatch_windows.py run --repair
"""

from __future__ import annotations

import os
import sys

# Ensure the package directory is importable when run as a loose script.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from netwatch.app import main  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(main())

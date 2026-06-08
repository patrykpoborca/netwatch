"""netwatch-pi — Raspberry Pi Wi-Fi network watchdog + log collection host.

This package implements a continuous network-health watchdog intended to run on
an always-on Raspberry Pi as a Wi-Fi vantage point, plus a lightweight stdlib
HTTP "collection host" so all logs (the Pi's own + a Windows desktop's pushed
logs) can be retrieved from one place.

The single CLI entrypoint is ``netwatch_pi.py`` at the project root, which simply
delegates to :func:`netwatch.cli.main`.
"""

__version__ = "1.0.0"

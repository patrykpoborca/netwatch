"""Command-line interface and subcommand dispatch for netwatch-pi.

Subcommands (per the spec, plus the user-requested ``serve``):
  run                 Continuous watchdog (``--serve`` to also start the collector).
  snapshot            Create a snapshot immediately, even if healthy.
  classify-latest     Read the latest event folder and print its diagnosis.
  install-service     Write + enable the systemd unit.
  uninstall-service   Disable + remove the systemd unit.
  serve               Start only the HTTP log-collection host.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import List, Optional

from . import checks, classify, collector, config as config_mod, service, snapshot
from .watchdog import Watchdog


def _find_latest_event(events_dir: str) -> Optional[str]:
    """Return the path of the most recently modified event folder/archive."""
    if not os.path.isdir(events_dir):
        return None
    candidates = []
    for name in os.listdir(events_dir):
        full = os.path.join(events_dir, name)
        candidates.append(full)
    if not candidates:
        return None
    candidates.sort(key=lambda p: os.path.getmtime(p) if os.path.exists(p) else 0)
    return candidates[-1]


# --------------------------------------------------------------------------- #
# Subcommand implementations
# --------------------------------------------------------------------------- #
def cmd_run(cfg, args) -> int:
    """Run the continuous watchdog, optionally with the collector in a thread."""
    serve = bool(args.serve)
    if serve and cfg.collector.get("enabled", True):
        try:
            collector.start_in_thread(cfg)
        except OSError as exc:
            # Bind failure shouldn't stop the watchdog.
            print(f"[collector] could not start server: {exc} (continuing watchdog)")
    elif serve:
        print("[collector] --serve requested but collector.enabled is false; skipping")

    Watchdog(cfg).run()
    return 0


def cmd_snapshot(cfg, args) -> int:
    """Capture a snapshot immediately, regardless of health."""
    sample = checks.gather_sample(cfg)
    classification = classify.classify_sample(sample)
    sample["classification"] = classification
    folder = snapshot.create_snapshot(
        cfg,
        classification,
        sample,
        [sample],
        prev_gateway_mac=sample.get("gateway_mac"),
    )
    print(f"Snapshot created: {folder}")
    print(f"Classification: {classification}")
    return 0


def cmd_classify_latest(cfg, args) -> int:
    """Read the latest event folder and print its summary/diagnosis."""
    latest = _find_latest_event(cfg.events_dir)
    if not latest:
        print(f"No events found in {cfg.events_dir}")
        return 1

    # Support both unzipped folders and .zip archives.
    summary = None
    if latest.endswith(".zip"):
        import zipfile

        try:
            with zipfile.ZipFile(latest) as zf:
                for member in zf.namelist():
                    if member.endswith("summary.json"):
                        summary = json.loads(zf.read(member).decode("utf-8"))
                        break
        except (zipfile.BadZipFile, OSError, json.JSONDecodeError) as exc:
            print(f"Could not read {latest}: {exc}")
            return 1
    else:
        summary_path = os.path.join(latest, "summary.json")
        try:
            with open(summary_path, "r", encoding="utf-8") as fh:
                summary = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            print(f"Could not read {summary_path}: {exc}")
            return 1

    if summary is None:
        print(f"No summary.json found in {latest}")
        return 1

    print(f"Latest event: {os.path.basename(latest)}")
    print(f"Classification: {summary.get('classification')}")
    print(f"\nPlain English:\n{summary.get('plain_english')}\n")
    print("Suspicious findings:")
    for f in summary.get("suspicious_findings", []):
        print(f"  - {f}")
    print("\nRecommended next steps:")
    for s in summary.get("recommended_next_steps", []):
        print(f"  - {s}")
    return 0


def cmd_install_service(cfg, args) -> int:
    """Install the systemd service. ``--no-serve`` drops --serve from ExecStart."""
    # The script path is the entrypoint the user invoked (netwatch_pi.py).
    script_path = args.script_path or os.path.abspath(sys.argv[0])
    config_path = cfg.path or config_mod.DEFAULT_CONFIG_PATH
    return service.install_service(
        script_path, config_path, serve=not args.no_serve
    )


def cmd_uninstall_service(cfg, args) -> int:
    return service.uninstall_service()


def cmd_serve(cfg, args) -> int:
    """Run only the HTTP log-collection host (blocking)."""
    if not cfg.collector.get("enabled", True):
        print("collector.enabled is false in config; enable it to use 'serve'.")
        return 1
    try:
        collector.serve_forever(cfg)
    except OSError as exc:
        print(f"[collector] could not bind: {exc}")
        return 1
    return 0


# --------------------------------------------------------------------------- #
# Argument parsing
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netwatch_pi.py",
        description="Raspberry Pi Wi-Fi network watchdog + log-collection host.",
    )
    parser.add_argument(
        "--config",
        default=None,
        help=f"Path to config.json (default: {config_mod.DEFAULT_CONFIG_PATH})",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_run = sub.add_parser("run", help="Continuous watchdog loop")
    p_run.add_argument(
        "--serve",
        action="store_true",
        help="Also start the HTTP log-collection host in a background thread",
    )
    p_run.set_defaults(func=cmd_run)

    p_snap = sub.add_parser("snapshot", help="Create a snapshot now, even if healthy")
    p_snap.set_defaults(func=cmd_snapshot)

    p_cl = sub.add_parser(
        "classify-latest", help="Print diagnosis from the latest event folder"
    )
    p_cl.set_defaults(func=cmd_classify_latest)

    p_inst = sub.add_parser("install-service", help="Write + enable the systemd unit")
    p_inst.add_argument(
        "--script-path",
        default=None,
        help="Absolute path to netwatch_pi.py to reference in ExecStart "
        "(default: the invoked script path)",
    )
    p_inst.add_argument(
        "--no-serve",
        action="store_true",
        help="Do not include --serve in the unit's ExecStart",
    )
    p_inst.set_defaults(func=cmd_install_service)

    p_uninst = sub.add_parser(
        "uninstall-service", help="Disable + remove the systemd unit"
    )
    p_uninst.set_defaults(func=cmd_uninstall_service)

    p_serve = sub.add_parser("serve", help="Run only the HTTP log-collection host")
    p_serve.set_defaults(func=cmd_serve)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """Entrypoint: parse args, load config, dispatch the subcommand."""
    parser = build_parser()
    args = parser.parse_args(argv)
    cfg = config_mod.load_config(args.config)
    try:
        return args.func(cfg, args)
    except KeyboardInterrupt:
        return 0

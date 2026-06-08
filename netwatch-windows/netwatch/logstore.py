"""JSONL sample logging plus log-swell control (rotation + retention).

Two responsibilities:

1. :class:`JsonlLogger` - append samples to ``netwatch-windows.jsonl`` and rotate by
   size. Rotated files are timestamped and (optionally) gzip-compressed. At most
   ``max_rotated_jsonl_files`` rotated files are kept; older ones are deleted.

2. :func:`prune_event_folders` - cap event snapshot folders by count and age. Oldest
   folders over the soft cap are compressed to ``.zip`` (auto-zip); everything beyond a
   hard cap is deleted so disk never grows unbounded.

Both are fully configurable via the ``log_management`` config section and are safe to
call repeatedly (idempotent / best-effort). Failures here never crash the watchdog.
"""

from __future__ import annotations

import gzip
import json
import os
import re
import shutil
import time
import zipfile
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .runner import CommandErrorLog


def _utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")


class JsonlLogger:
    """Append-only JSONL writer with size-based rotation + gzip + retention."""

    def __init__(
        self,
        jsonl_path: str,
        *,
        max_mb: float = 50,
        max_rotated_files: int = 5,
        gzip_rotated: bool = True,
    ) -> None:
        self.jsonl_path = jsonl_path
        self.max_bytes = int(max_mb * 1024 * 1024)
        self.max_rotated_files = int(max_rotated_files)
        self.gzip_rotated = bool(gzip_rotated)
        os.makedirs(os.path.dirname(os.path.abspath(jsonl_path)), exist_ok=True)

    def append(self, sample: Dict[str, Any]) -> None:
        """Append one sample as a JSON line, rotating first if over the size cap."""
        self._maybe_rotate()
        line = json.dumps(sample, ensure_ascii=False, separators=(",", ":"))
        with open(self.jsonl_path, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")

    def _maybe_rotate(self) -> None:
        try:
            if not os.path.isfile(self.jsonl_path):
                return
            if os.path.getsize(self.jsonl_path) < self.max_bytes:
                return
        except OSError:
            return

        base = self.jsonl_path
        stamp = _utc_stamp()
        rotated = f"{base}.{stamp}"
        try:
            os.replace(base, rotated)
        except OSError:
            return

        if self.gzip_rotated:
            gz = rotated + ".gz"
            try:
                with open(rotated, "rb") as src, gzip.open(gz, "wb") as dst:
                    shutil.copyfileobj(src, dst)
                os.remove(rotated)
            except OSError:
                pass  # keep the uncompressed rotated file if gzip failed

        self._enforce_rotated_retention()

    def _enforce_rotated_retention(self) -> None:
        """Keep at most ``max_rotated_files`` rotated files; delete the oldest."""
        d = os.path.dirname(os.path.abspath(self.jsonl_path))
        base_name = os.path.basename(self.jsonl_path)
        pattern = re.compile(re.escape(base_name) + r"\.\d{8}_\d{6}(\.gz)?$")
        rotated = []
        try:
            for fn in os.listdir(d):
                if pattern.match(fn):
                    full = os.path.join(d, fn)
                    rotated.append((os.path.getmtime(full), full))
        except OSError:
            return
        rotated.sort(reverse=True)  # newest first
        for _, full in rotated[self.max_rotated_files:]:
            try:
                os.remove(full)
            except OSError:
                pass


# ---------------------------------------------------------------------------
# Event folder retention
# ---------------------------------------------------------------------------

_EVENT_DIR_RE = re.compile(r"^\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}_windows_")


def _event_items(events_dir: str) -> List[Dict[str, Any]]:
    """List event snapshots (folders and already-zipped events) with mtime/age."""
    items: List[Dict[str, Any]] = []
    if not os.path.isdir(events_dir):
        return items
    now = time.time()
    for name in os.listdir(events_dir):
        full = os.path.join(events_dir, name)
        is_zip = name.endswith(".zip") and _EVENT_DIR_RE.match(name[:-4] or "")
        is_dir = os.path.isdir(full) and _EVENT_DIR_RE.match(name)
        if not (is_zip or is_dir):
            continue
        try:
            mtime = os.path.getmtime(full)
        except OSError:
            continue
        items.append(
            {
                "path": full,
                "name": name,
                "mtime": mtime,
                "age_days": (now - mtime) / 86400.0,
                "is_zip": bool(is_zip),
                "is_dir": bool(is_dir),
            }
        )
    items.sort(key=lambda x: x["mtime"])  # oldest first
    return items


def prune_event_folders(
    events_dir: str,
    *,
    max_folders: int = 50,
    max_age_days: int = 30,
    auto_zip: bool = True,
    hard_cap_items: int = 200,
    error_log: Optional[CommandErrorLog] = None,
) -> Dict[str, int]:
    """Apply retention policy to event snapshots.

    Steps (best-effort, never raises):

    1. Delete any item older than ``max_age_days``.
    2. If over ``max_folders``, compress the oldest *uncompressed folders* to ``.zip``
       (when ``auto_zip``), reclaiming space while preserving evidence.
    3. If still over ``hard_cap_items`` total items, delete the oldest items outright so
       disk never grows unbounded.

    Returns a small stats dict for logging.
    """
    stats = {"zipped": 0, "deleted_age": 0, "deleted_cap": 0}
    try:
        items = _event_items(events_dir)

        # 1. Age-based pruning.
        if max_age_days and max_age_days > 0:
            survivors = []
            for it in items:
                if it["age_days"] > max_age_days:
                    if _remove_item(it):
                        stats["deleted_age"] += 1
                else:
                    survivors.append(it)
            items = survivors

        # 2. Over the soft folder cap: zip oldest uncompressed folders.
        if auto_zip and len(items) > max_folders:
            overflow = len(items) - max_folders
            for it in list(items):
                if overflow <= 0:
                    break
                if it["is_dir"]:
                    if _zip_folder(it["path"]):
                        stats["zipped"] += 1
                    overflow -= 1
            items = _event_items(events_dir)  # refresh after zipping

        # 3. Hard cap: delete oldest items beyond the absolute limit.
        if hard_cap_items and hard_cap_items > 0 and len(items) > hard_cap_items:
            for it in items[: len(items) - hard_cap_items]:
                if _remove_item(it):
                    stats["deleted_cap"] += 1
    except Exception as exc:  # noqa: BLE001 - retention must never crash the loop
        if error_log is not None:
            error_log.record_raw("prune_event_folders", f"{type(exc).__name__}: {exc}")
    return stats


def _remove_item(item: Dict[str, Any]) -> bool:
    try:
        if item["is_dir"]:
            shutil.rmtree(item["path"], ignore_errors=True)
        else:
            os.remove(item["path"])
        return True
    except OSError:
        return False


def _zip_folder(folder_path: str) -> bool:
    """Compress ``folder_path`` to ``folder_path.zip`` and remove the original folder."""
    zip_path = folder_path.rstrip("\\/") + ".zip"
    try:
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for root, _dirs, files in os.walk(folder_path):
                for f in files:
                    fp = os.path.join(root, f)
                    arc = os.path.relpath(fp, os.path.dirname(folder_path))
                    zf.write(fp, arc)
        shutil.rmtree(folder_path, ignore_errors=True)
        return True
    except OSError:
        # Clean up a partial zip on failure.
        try:
            if os.path.isfile(zip_path):
                os.remove(zip_path)
        except OSError:
            pass
        return False


def zip_event_folder(folder_path: str) -> Optional[str]:
    """Public helper: zip a single event folder (used by `export latest as ZIP` / push).

    Returns the zip path on success, None on failure. Does NOT delete the source folder.
    """
    zip_path = folder_path.rstrip("\\/") + ".zip"
    try:
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for root, _dirs, files in os.walk(folder_path):
                for f in files:
                    fp = os.path.join(root, f)
                    arc = os.path.relpath(fp, os.path.dirname(folder_path))
                    zf.write(fp, arc)
        return zip_path
    except OSError:
        return None

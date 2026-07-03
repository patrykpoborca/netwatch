"""SD-card / log-swell control: JSONL rotation, event-folder retention, pruning.

The Pi runs off an SD card, so this module exists to bound disk usage and keep
write amplification low:

  * JSONL is rotated by size (gzip the old file, keep N rotations, delete older).
  * Event folders are capped by count and age; the oldest are zipped, then any
    beyond a hard cap are deleted so the card can never fill.
  * The same retention is applied to the collector's ``incoming_dir`` (pushed
    Windows logs), plus a total-size cap (``max_incoming_mb``).

All functions are best-effort and never raise into the caller — disk-management
failures must not take down the watchdog loop.
"""

from __future__ import annotations

import gzip
import os
import shutil
import threading
import time
import zipfile
from datetime import datetime
from typing import List, Optional


# --------------------------------------------------------------------------- #
# Per-path locks, so concurrent appenders (e.g. the collector's threaded HTTP
# server handling multiple pushes for the same host_label at once) can't race
# the check-then-rotate-then-append sequence and silently drop/duplicate lines.
#
# A bounded pool indexed by a hash of the normalized path is used rather than
# one lock per distinct path: a per-path dict would grow without bound as new
# host_labels are pushed (an attacker on an open, unauthenticated LAN
# collector could push under many unique host_labels purely to grow it), and
# normalizing the path first ensures two different spellings of the same file
# (relative vs. absolute, redundant slashes) always map to the same lock.
# Collisions just mean two unrelated paths occasionally share a lock, which
# costs a little contention — never correctness — at this device's tiny
# concurrent-write volume.
# --------------------------------------------------------------------------- #
_PATH_LOCK_POOL_SIZE = 64
_path_lock_pool = [threading.Lock() for _ in range(_PATH_LOCK_POOL_SIZE)]
# Dedicated lock serializing the incoming-directory retention passes
# themselves (see ``prune_incoming_events`` / ``enforce_incoming_cap``), since
# those touch many files/directories at once and must not interleave.
_retention_lock = threading.Lock()


def _lock_for(path: str) -> threading.Lock:
    normalized = os.path.normpath(os.path.abspath(path))
    return _path_lock_pool[hash(normalized) % _PATH_LOCK_POOL_SIZE]


# --------------------------------------------------------------------------- #
# JSONL appender (low write amplification)
# --------------------------------------------------------------------------- #
class JsonlAppender:
    """Append JSONL lines via open-append-write-flush.

    We open the file in append mode, write one line, flush to the OS buffer, and
    rely on normal OS write-back rather than fsync-per-line. This avoids the
    write amplification of rewriting the whole file and the SD-card wear of an
    fsync on every sample, while still being durable within seconds. Rotation is
    checked cheaply via os.stat before each write.

    Appends are serialized per-path (see ``_lock_for``) so that two threads
    writing the same file (e.g. two concurrent pushes for the same
    ``host_label``) cannot both trigger rotation at once or have a write land
    between another thread's rotate-copy and truncate.
    """

    def __init__(self, path: str, max_bytes: int, max_rotated: int):
        self.path = path
        self.max_bytes = max_bytes
        self.max_rotated = max_rotated
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)

    def append(self, line: str) -> None:
        """Append a single line (without trailing newline) safely."""
        self.append_many([line])

    def append_many(self, lines) -> None:
        """Append many lines under ONE lock/open/rotate-check.

        Used by the collector's sample ingest so a batch of N pushed samples
        costs one open-append-flush pass instead of N (each ``append`` call
        re-opens the file and re-stats it for rotation). Rotation is checked
        once up front; a batch may therefore overshoot ``max_bytes`` by one
        batch's worth of small lines, which the next write corrects.
        """
        if not lines:
            return
        try:
            with _lock_for(self.path):
                self._maybe_rotate()
                with open(self.path, "a", encoding="utf-8") as fh:
                    for line in lines:
                        fh.write(line + "\n")
                    fh.flush()  # hand off to OS; no per-line fsync (SD-card friendly)
        except OSError:
            # Never let a logging failure kill the loop.
            pass

    def _maybe_rotate(self) -> None:
        try:
            size = os.path.getsize(self.path)
        except OSError:
            return
        if size < self.max_bytes:
            return
        rotate_jsonl(self.path, self.max_rotated)


def rotate_jsonl(path: str, max_rotated: int) -> Optional[str]:
    """Gzip ``path`` to a timestamped file and prune to ``max_rotated`` copies.

    Returns the rotated filename on success, else None. The live file is then
    recreated empty so appends continue seamlessly.
    """
    if not os.path.exists(path):
        return None
    try:
        stamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        base = os.path.basename(path)
        rotated = os.path.join(os.path.dirname(path), f"{base}.{stamp}.gz")
        with open(path, "rb") as src, gzip.open(rotated, "wb") as dst:
            shutil.copyfileobj(src, dst)
        # Truncate the live file rather than unlink+recreate (keeps inode/fd-safe).
        open(path, "w", encoding="utf-8").close()
        _prune_rotations(path, max_rotated)
        return rotated
    except OSError:
        return None


def _prune_rotations(path: str, max_rotated: int) -> None:
    """Keep only the newest ``max_rotated`` ``<base>.*.gz`` rotations."""
    directory = os.path.dirname(path) or "."
    base = os.path.basename(path)
    try:
        candidates = [
            os.path.join(directory, f)
            for f in os.listdir(directory)
            if f.startswith(base + ".") and f.endswith(".gz")
        ]
    except OSError:
        return
    candidates.sort(key=_safe_mtime, reverse=True)
    for old in candidates[max_rotated:]:
        try:
            os.remove(old)
        except OSError:
            pass


# --------------------------------------------------------------------------- #
# Event-folder retention
# --------------------------------------------------------------------------- #
def _safe_mtime(path: str) -> float:
    try:
        return os.path.getmtime(path)
    except OSError:
        return 0.0


def _list_event_dirs(events_dir: str) -> List[str]:
    try:
        entries = [
            os.path.join(events_dir, d)
            for d in os.listdir(events_dir)
            if os.path.isdir(os.path.join(events_dir, d))
        ]
    except OSError:
        return []
    entries.sort(key=_safe_mtime)  # oldest first
    return entries


def zip_event_folder(folder: str, remove_original: bool = True) -> Optional[str]:
    """Zip an event folder to ``<folder>.zip`` and optionally remove the dir."""
    if not os.path.isdir(folder):
        return None
    archive = folder.rstrip("/") + ".zip"
    try:
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zf:
            for root, _dirs, files in os.walk(folder):
                for fname in files:
                    full = os.path.join(root, fname)
                    arcname = os.path.relpath(full, os.path.dirname(folder))
                    zf.write(full, arcname)
        if remove_original:
            shutil.rmtree(folder, ignore_errors=True)
        return archive
    except OSError:
        return None


def prune_event_folders(
    events_dir: str,
    max_folders: int,
    max_age_days: int,
) -> None:
    """Enforce event-folder retention.

    Strategy:
      1. Zip (and remove the unzipped dir of) any event folder older than
         ``max_age_days`` — keeps the evidence but compressed.
      2. If the number of *unzipped* folders still exceeds ``max_folders``, zip
         the oldest until at/under the cap.
      3. Hard cap: if the total number of archives+folders exceeds 2x
         ``max_folders``, delete the oldest archives so the card can't fill.
    """
    if not os.path.isdir(events_dir):
        return

    now = time.time()
    age_limit = max_age_days * 86400

    # 1. Age-based zipping.
    for folder in _list_event_dirs(events_dir):
        if now - _safe_mtime(folder) > age_limit:
            zip_event_folder(folder, remove_original=True)

    # 2. Count-based zipping of oldest unzipped folders.
    folders = _list_event_dirs(events_dir)
    excess = len(folders) - max_folders
    for folder in folders[:max(0, excess)]:
        zip_event_folder(folder, remove_original=True)

    # 3. Hard cap on archives so the SD card cannot fill.
    try:
        archives = [
            os.path.join(events_dir, f)
            for f in os.listdir(events_dir)
            if f.endswith(".zip")
        ]
    except OSError:
        archives = []
    archives.sort(key=_safe_mtime)  # oldest first
    hard_cap = max_folders * 2
    if len(archives) > hard_cap:
        for old in archives[: len(archives) - hard_cap]:
            try:
                os.remove(old)
            except OSError:
                pass


# --------------------------------------------------------------------------- #
# Incoming (pushed-host logs) size enforcement
# --------------------------------------------------------------------------- #
def dir_size_bytes(path: str) -> int:
    """Total size of all files under ``path`` (best-effort)."""
    total = 0
    if not os.path.isdir(path):
        return 0
    for root, _dirs, files in os.walk(path):
        for fname in files:
            try:
                total += os.path.getsize(os.path.join(root, fname))
            except OSError:
                pass
    return total


def enforce_incoming_cap(incoming_dir: str, max_mb: int) -> None:
    """Delete oldest files under ``incoming_dir`` until under ``max_mb``.

    Protects the SD card from unbounded pushed logs. Newest files (most recent
    evidence) are preserved; oldest are removed first.

    Serialized on ``_retention_lock``: the collector's threaded HTTP server
    can call this (via ``_enforce_incoming_retention``) from multiple request
    threads at once, and interleaved listing/deletion of the same files could
    otherwise raise spurious ``OSError``s or race with ``prune_incoming_events``
    zipping/removing the same folders concurrently.
    """
    if not os.path.isdir(incoming_dir):
        return
    with _retention_lock:
        max_bytes = max_mb * 1024 * 1024
        if dir_size_bytes(incoming_dir) <= max_bytes:
            return

        # Collect all files with mtimes, oldest first, delete until under cap.
        files: List[str] = []
        for root, _dirs, names in os.walk(incoming_dir):
            for n in names:
                files.append(os.path.join(root, n))
        files.sort(key=_safe_mtime)

        for f in files:
            if dir_size_bytes(incoming_dir) <= max_bytes:
                break
            try:
                os.remove(f)
            except OSError:
                pass

        _remove_empty_dirs(incoming_dir)


def _remove_empty_dirs(root_dir: str, min_age_seconds: float = 10.0) -> None:
    """Remove now-empty subdirectories under (but not including) ``root_dir``.

    File-only pruning (as in ``enforce_incoming_cap``) can leave behind empty
    ``<host>/events/<event_id>`` directories once their files are deleted;
    left unchecked these accumulate and can exhaust inodes even while staying
    under the byte cap.

    Directories younger than ``min_age_seconds`` are left alone: an ingest
    handler ``os.makedirs``'s the event directory and then writes
    ``summary.json``/``event.zip`` into it as two separate steps, so a
    concurrent retention pass could otherwise observe it as briefly empty and
    delete it out from under that in-flight write.
    """
    now = time.time()
    for current, _dirs, _files in os.walk(root_dir, topdown=False):
        if current == root_dir:
            continue
        try:
            if not os.listdir(current) and now - os.path.getmtime(current) > min_age_seconds:
                os.rmdir(current)
        except OSError:
            pass


# This collector is designed for a small, known number of pushing hosts
# (typically exactly one Windows desktop paired with the Pi). Per-host
# retention alone bounds each host_label's own event count, but not the
# *number* of host_labels: on an open LAN collector (default auth_token is
# null) an attacker can vary host_label on every request so each fake host's
# events dir individually stays under max_folders while the total number of
# host directories — and their inode cost — still grows without bound. Cap
# the number of distinct host directories retained, regardless of how few
# events each one holds.
MAX_INCOMING_HOSTS = 32


def _host_last_activity(host_dir: str) -> float:
    """Most recent mtime of anything under ``host_dir`` (best-effort)."""
    latest = _safe_mtime(host_dir)
    for root, _dirs, files in os.walk(host_dir):
        for fname in files:
            latest = max(latest, _safe_mtime(os.path.join(root, fname)))
    return latest


def _prune_excess_hosts(incoming_dir: str, max_hosts: int) -> None:
    """Delete whole host directories, oldest-activity-first, beyond ``max_hosts``.

    Complements the per-host event retention in ``prune_incoming_events``: that
    bounds each host's own folder count, this bounds how many distinct hosts
    are retained at all.
    """
    try:
        host_dirs = [
            os.path.join(incoming_dir, d)
            for d in os.listdir(incoming_dir)
            if os.path.isdir(os.path.join(incoming_dir, d))
        ]
    except OSError:
        return
    if len(host_dirs) <= max_hosts:
        return
    host_dirs.sort(key=_host_last_activity)  # oldest activity first
    excess = len(host_dirs) - max_hosts
    for host_dir in host_dirs[:excess]:
        shutil.rmtree(host_dir, ignore_errors=True)


def prune_incoming_events(
    incoming_dir: str,
    max_folders: int,
    max_age_days: int,
) -> None:
    """Apply event-folder retention to every pushed host's events directory.

    ``incoming_dir`` holds one subdirectory per ``host_label`` that has pushed
    samples/events (e.g. ``incoming_dir/windows-desktop/events/<event_id>/``).
    Without this, pushed event folders were never pruned by count or age (only
    ``enforce_incoming_cap``'s total-byte cap applied, which deletes files but
    not directories) — an open collector on the LAN could be spammed with
    unique event_ids to grow the directory tree without bound. This mirrors
    the retention already applied to the Pi's own ``events_dir``. It also
    enforces ``MAX_INCOMING_HOSTS`` (see ``_prune_excess_hosts``) so varying
    ``host_label`` itself can't be used to the same end.

    Serialized on ``_retention_lock``: this is called synchronously after
    every event ingest on the threaded HTTP server, so concurrent pushes
    (possibly for different hosts) could otherwise zip/delete the same event
    folders at the same time, corrupting an in-progress zip or raising
    spurious errors.
    """
    if not os.path.isdir(incoming_dir):
        return
    with _retention_lock:
        try:
            hosts = [
                d for d in os.listdir(incoming_dir)
                if os.path.isdir(os.path.join(incoming_dir, d))
            ]
        except OSError:
            return

        for host in hosts:
            host_dir = os.path.join(incoming_dir, host)
            events_dir = os.path.join(host_dir, "events")
            if os.path.isdir(events_dir):
                prune_event_folders(events_dir, max_folders, max_age_days)

        _prune_excess_hosts(incoming_dir, MAX_INCOMING_HOSTS)
        _remove_empty_dirs(incoming_dir)


def run_retention_pass(cfg) -> None:
    """Run the full retention/prune pass (JSONL + events + incoming).

    Called at startup and periodically during ``run``. Best-effort; never raises
    — a malformed/partial ``log_management`` or ``collector`` config section
    (e.g. a key explicitly set to ``null`` in config.json, which survives the
    deep-merge as ``None`` rather than falling back to the default) must
    degrade to a no-op pass rather than crash this background task, per the
    module's stated contract.
    """
    lm = cfg.log_management or {}
    # JSONL rotation check (in case it grew while idle / on startup).
    try:
        jpath = cfg["jsonl_log_path"]
        max_bytes = int(lm["max_jsonl_mb"]) * 1024 * 1024
        if os.path.exists(jpath) and os.path.getsize(jpath) >= max_bytes:
            # Serialize with JsonlAppender's own lock: without this, a
            # concurrent append (same path) could land between this rotate's
            # gzip-copy and truncate and be silently discarded.
            with _lock_for(jpath):
                rotate_jsonl(jpath, int(lm["max_rotated_jsonl_files"]))
    except (OSError, KeyError, ValueError, TypeError):
        pass

    # Event-folder retention.
    try:
        prune_event_folders(
            cfg.events_dir,
            int(lm["max_event_folders"]),
            int(lm["max_event_age_days"]),
        )
    except (KeyError, ValueError, TypeError):
        pass

    # Incoming (pushed) logs retention.
    try:
        collector = cfg.collector or {}
        incoming = collector.get("incoming_dir")
        if incoming:
            prune_incoming_events(
                incoming,
                int(lm["max_event_folders"]),
                int(lm["max_event_age_days"]),
            )
            enforce_incoming_cap(incoming, int(collector["max_incoming_mb"]))
    except (KeyError, ValueError, TypeError):
        pass

"""Lightweight log-collection HTTP host (stdlib only — no Flask/FastAPI).

This turns the Pi into a single place to retrieve all logs:
  * READ endpoints expose the Pi's own samples/events.
  * INGEST endpoints let the Windows desktop push its samples/events to the Pi.

It is built on ``http.server`` + ``socketserver`` and runs either as its own
subcommand (``serve``) or in a background thread alongside ``run --serve``.

Robustness:
  * The server is wrapped so an exception never propagates into / kills the
    watchdog thread.
  * Bad requests return proper 4xx; request bodies are size-limited.
  * ``event_id`` / ``host_label`` are sanitized against path traversal.
  * The same SD-card retention/caps are applied to the incoming directory.

Security:
  * Optional bearer auth: if ``collector.auth_token`` is set, every endpoint
    requires ``Authorization: Bearer <token>``; otherwise the server is open and
    assumes a trusted LAN (documented in the README, with the runbook's privacy
    note: logs may contain IPs/MACs/DNS queries/hostnames — keep them local).

==========================  HTTP CONTRACT  ==================================
READ:
  GET  /health                       -> {"status":"ok", ...}
  GET  /samples/latest?n=100         -> {"samples":[...]}  (last N Pi samples)
  GET  /events                       -> {"events":[{id,classification,time,size_bytes}]}
  GET  /events/{event_id}            -> that event's summary.json (object)
  GET  /events/{event_id}/download   -> application/zip (streamed)
  GET  /collected                    -> {"hosts":[{host_label, samples, events:[...]}]}
INGEST (from Windows desktop):
  POST /ingest/samples
       body: a single sample object  OR  {"samples":[ {...}, ... ]}
       -> appends to incoming_dir/<host_label>/samples.jsonl
       (host_label taken from each sample's "host_label", default "unknown-host")
  POST /ingest/events
       Content-Type: application/json
         body: {"host_label","event_id","classification","summary":{...}}
         -> stores incoming_dir/<host_label>/events/<event_id>/summary.json
       Content-Type: application/zip (binary)
         query: ?host_label=...&event_id=...&classification=...
         -> stores the uploaded zip under that event folder, enforcing max size
Auth (all endpoints, if auth_token set): Authorization: Bearer <token>; else 401.
============================================================================
"""

from __future__ import annotations

import hmac
import json
import os
import re
import shutil
import tempfile
import threading
import zipfile
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import BytesIO
from typing import Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlparse

from . import logmgmt

# Hard limits to keep the server safe on a small device.
MAX_JSON_BODY_BYTES = 8 * 1024 * 1024       # 8 MB for JSON ingest
MAX_ZIP_BODY_BYTES = 64 * 1024 * 1024       # 64 MB per uploaded event zip
# Cap on the *uncompressed* size of an ingested zip. Checked against the
# central directory (cheap) before ``testzip()`` (which fully decompresses
# every member) so a small, highly-compressible "zip bomb" body can't pin the
# CPU decompressing gigabytes on a low-powered Pi.
MAX_ZIP_UNCOMPRESSED_BYTES = 256 * 1024 * 1024  # 256 MB
SAMPLE_TAIL_DEFAULT = 100
SAMPLE_TAIL_MAX = 5000
# Chunk size used when streaming file/zip responses to avoid buffering
# multi-MB event archives entirely in memory.
STREAM_CHUNK_BYTES = 64 * 1024


def _sanitize_label(value: Optional[str], fallback: str = "unknown-host") -> str:
    """Sanitize a host_label/event_id to a safe single path segment.

    Strips any path separators and restricts to a safe charset so a malicious
    or buggy client cannot perform path traversal.
    """
    if not value:
        return fallback
    # Keep only safe characters; collapse everything else.
    cleaned = re.sub(r"[^A-Za-z0-9._-]", "_", str(value))
    cleaned = cleaned.strip("._") or fallback
    # Defense in depth: never allow traversal tokens.
    if cleaned in (".", "..") or "/" in cleaned or "\\" in cleaned:
        return fallback
    return cleaned[:128]


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class CollectorServer:
    """Owns config + provides the request-handling logic for the HTTP server."""

    def __init__(self, cfg):
        self.cfg = cfg
        self.collector_cfg = cfg.collector
        self.incoming_dir = self.collector_cfg["incoming_dir"]
        self.auth_token = self.collector_cfg.get("auth_token")
        self.jsonl_path = cfg["jsonl_log_path"]
        self.events_dir = cfg.events_dir
        os.makedirs(self.incoming_dir, exist_ok=True)

    # ---------------------------- auth ----------------------------------- #
    def check_auth(self, header_value: Optional[str]) -> bool:
        """Return True if the request is authorized."""
        if not self.auth_token:
            return True  # open server (LAN-trusted)
        if not header_value:
            return False
        expected = f"Bearer {self.auth_token}"
        # Constant-time comparison: this token is the *only* access control
        # once an operator exposes the collector beyond the LAN, so a
        # short-circuiting `==` would let an attacker recover it byte-by-byte
        # via response timing.
        return hmac.compare_digest(header_value, expected)

    # ------------------------- READ handlers ----------------------------- #
    def health(self) -> Dict:
        return {
            "status": "ok",
            "service": "netwatch-pi-collector",
            "host_label": self.cfg["host_label"],
            "time": _utc_now_iso(),
            "auth_required": bool(self.auth_token),
        }

    def latest_samples(self, n: int) -> Dict:
        """Return the last ``n`` lines of the Pi's own JSONL as parsed objects."""
        n = max(1, min(int(n), SAMPLE_TAIL_MAX))
        lines = _tail_lines(self.jsonl_path, n)
        samples: List[Dict] = []
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                samples.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return {"count": len(samples), "samples": samples}

    def list_events(self) -> Dict:
        """List the Pi's own event folders (and zipped archives)."""
        events: List[Dict] = []
        if os.path.isdir(self.events_dir):
            for name in sorted(os.listdir(self.events_dir)):
                full = os.path.join(self.events_dir, name)
                classification = _classification_from_name(name)
                if os.path.isdir(full):
                    events.append(
                        {
                            "id": name,
                            "classification": classification,
                            "time": _mtime_iso(full),
                            "size_bytes": logmgmt.dir_size_bytes(full),
                            "archived": False,
                        }
                    )
                elif name.endswith(".zip"):
                    events.append(
                        {
                            "id": name[:-4],
                            "classification": classification,
                            "time": _mtime_iso(full),
                            "size_bytes": _safe_size(full),
                            "archived": True,
                        }
                    )
        return {"count": len(events), "events": events}

    def event_summary(self, event_id: str) -> Tuple[int, Dict]:
        """Return (status, summary.json object) for an event, or 404."""
        event_id = _sanitize_label(event_id, fallback="")
        if not event_id:
            return 404, {"error": "event not found"}
        folder = os.path.join(self.events_dir, event_id)
        summary_path = os.path.join(folder, "summary.json")
        if os.path.isfile(summary_path):
            try:
                with open(summary_path, "r", encoding="utf-8") as fh:
                    return 200, json.load(fh)
            except (OSError, json.JSONDecodeError):
                return 500, {"error": "could not read summary.json"}
        return 404, {"error": "event not found"}

    def event_zip_path(self, event_id: str) -> Optional[Tuple[str, bool]]:
        """Return (path, is_temp) to a zip file for the event, or None.

        Returns the already-stored ``<event>.zip`` archive directly when one
        exists, or builds one on disk (never fully in memory) for a live
        event folder. The caller streams the file to the response and, if
        ``is_temp`` is True, must delete it afterwards.
        """
        event_id = _sanitize_label(event_id, fallback="")
        if not event_id:
            return None
        folder = os.path.join(self.events_dir, event_id)
        archive = folder + ".zip"
        if os.path.isfile(archive):
            return archive, False
        if os.path.isdir(folder):
            fd, tmp_path = tempfile.mkstemp(prefix="netwatch-event-", suffix=".zip")
            os.close(fd)
            try:
                with zipfile.ZipFile(tmp_path, "w", zipfile.ZIP_DEFLATED) as zf:
                    for root, _dirs, files in os.walk(folder):
                        for fname in files:
                            full = os.path.join(root, fname)
                            arc = os.path.relpath(full, os.path.dirname(folder))
                            zf.write(full, arc)
                return tmp_path, True
            except OSError:
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass
                return None
        return None

    def list_collected(self) -> Dict:
        """List logs/events received from other hosts (e.g. the Windows desktop)."""
        hosts: List[Dict] = []
        if os.path.isdir(self.incoming_dir):
            for host in sorted(os.listdir(self.incoming_dir)):
                hdir = os.path.join(self.incoming_dir, host)
                if not os.path.isdir(hdir):
                    continue
                samples_path = os.path.join(hdir, "samples.jsonl")
                events_dir = os.path.join(hdir, "events")
                host_events: List[Dict] = []
                if os.path.isdir(events_dir):
                    for ev in sorted(os.listdir(events_dir)):
                        evp = os.path.join(events_dir, ev)
                        host_events.append(
                            {
                                "id": ev,
                                "time": _mtime_iso(evp),
                                "size_bytes": (
                                    logmgmt.dir_size_bytes(evp)
                                    if os.path.isdir(evp)
                                    else _safe_size(evp)
                                ),
                            }
                        )
                hosts.append(
                    {
                        "host_label": host,
                        "samples_file_exists": os.path.isfile(samples_path),
                        "samples_size_bytes": _safe_size(samples_path),
                        "events": host_events,
                    }
                )
        return {"count": len(hosts), "hosts": hosts}

    # ------------------------ INGEST handlers ---------------------------- #
    def ingest_samples(self, body: bytes) -> Tuple[int, Dict]:
        """Append one or many pushed samples into per-host samples.jsonl."""
        try:
            data = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return 400, {"error": "invalid JSON body"}

        if isinstance(data, dict) and "samples" in data:
            samples = data.get("samples")
        elif isinstance(data, dict):
            samples = [data]  # single sample object
        elif isinstance(data, list):
            samples = data
        else:
            return 400, {"error": "expected object or {'samples': [...]}"}

        if not isinstance(samples, list):
            return 400, {"error": "'samples' must be a list"}

        written = 0
        per_host: Dict[str, List[str]] = {}
        for s in samples:
            if not isinstance(s, dict):
                continue
            host = _sanitize_label(s.get("host_label"), fallback="unknown-host")
            per_host.setdefault(host, []).append(json.dumps(s))

        for host, lines in per_host.items():
            hdir = os.path.join(self.incoming_dir, host)
            os.makedirs(hdir, exist_ok=True)
            path = os.path.join(hdir, "samples.jsonl")
            # Rotate pushed samples too (reuse the SD-card-safe appender logic).
            appender = logmgmt.JsonlAppender(
                path,
                max_bytes=int(self.cfg.log_management["max_jsonl_mb"]) * 1024 * 1024,
                max_rotated=int(self.cfg.log_management["max_rotated_jsonl_files"]),
            )
            for line in lines:
                appender.append(line)
                written += 1

        # Enforce the incoming size cap after writing.
        logmgmt.enforce_incoming_cap(
            self.incoming_dir, int(self.collector_cfg["max_incoming_mb"])
        )
        return 200, {"status": "ok", "written": written}

    def ingest_event_json(self, body: bytes) -> Tuple[int, Dict]:
        """Store a pushed event's summary.json under the host's events dir."""
        try:
            data = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return 400, {"error": "invalid JSON body"}
        if not isinstance(data, dict):
            return 400, {"error": "expected JSON object"}

        host = _sanitize_label(data.get("host_label"), fallback="unknown-host")
        event_id = _sanitize_label(data.get("event_id"), fallback="")
        if not event_id:
            return 400, {"error": "event_id is required"}
        summary = data.get("summary")
        if not isinstance(summary, dict):
            # Allow the top-level fields to act as the summary if none given.
            summary = {
                k: data.get(k)
                for k in ("event_id", "classification", "host_label")
                if k in data
            }

        ev_dir = os.path.join(self.incoming_dir, host, "events", event_id)
        os.makedirs(ev_dir, exist_ok=True)
        try:
            with open(os.path.join(ev_dir, "summary.json"), "w", encoding="utf-8") as fh:
                json.dump(summary, fh, indent=2)
        except OSError as exc:
            return 500, {"error": f"could not store summary: {exc}"}

        self._enforce_incoming_retention()
        return 200, {"status": "ok", "host_label": host, "event_id": event_id}

    def ingest_event_zip(
        self, body: bytes, query: Dict[str, List[str]]
    ) -> Tuple[int, Dict]:
        """Store a pushed binary (zip) event upload, enforcing size caps."""
        host = _sanitize_label(_first(query, "host_label"), fallback="unknown-host")
        event_id = _sanitize_label(_first(query, "event_id"), fallback="")
        if not event_id:
            return 400, {"error": "event_id query parameter is required"}

        if len(body) > MAX_ZIP_BODY_BYTES:
            return 413, {"error": "uploaded event too large"}
        # Validate it is actually a zip before storing.
        try:
            with zipfile.ZipFile(BytesIO(body)) as zf:
                # Check the (cheap, central-directory-only) uncompressed total
                # *before* testzip(), which fully decompresses every member.
                # Without this, a small, highly-compressible body can force
                # the handler thread to spend a long time (and steady CPU)
                # decompressing a "zip bomb" — a CPU-exhaustion DoS on a
                # low-powered Pi that's reachable by anyone on the LAN when
                # auth_token is unset (the default).
                total_uncompressed = sum(zi.file_size for zi in zf.infolist())
                if total_uncompressed > MAX_ZIP_UNCOMPRESSED_BYTES:
                    return 400, {"error": "zip expands too large; rejected"}
                if zf.testzip() is not None:
                    return 400, {"error": "corrupt zip upload"}
        except zipfile.BadZipFile:
            return 400, {"error": "body is not a valid zip"}

        ev_dir = os.path.join(self.incoming_dir, host, "events", event_id)
        os.makedirs(ev_dir, exist_ok=True)
        try:
            with open(os.path.join(ev_dir, "event.zip"), "wb") as fh:
                fh.write(body)
        except OSError as exc:
            return 500, {"error": f"could not store zip: {exc}"}

        self._enforce_incoming_retention()
        return 200, {"status": "ok", "host_label": host, "event_id": event_id}

    def _enforce_incoming_retention(self) -> None:
        """Apply both folder-count/age retention and the total-byte cap.

        Run synchronously after every event ingest (in addition to the
        periodic ``run_retention_pass``) so a burst of pushed events from an
        open LAN collector can't grow unbounded between prune passes
        (default ``prune_interval_seconds`` is 3600s).
        """
        lm = self.cfg.log_management
        logmgmt.prune_incoming_events(
            self.incoming_dir,
            int(lm["max_event_folders"]),
            int(lm["max_event_age_days"]),
        )
        logmgmt.enforce_incoming_cap(
            self.incoming_dir, int(self.collector_cfg["max_incoming_mb"])
        )


# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #
def _first(query: Dict[str, List[str]], key: str) -> Optional[str]:
    vals = query.get(key)
    return vals[0] if vals else None


def _safe_size(path: str) -> int:
    try:
        return os.path.getsize(path)
    except OSError:
        return 0


def _mtime_iso(path: str) -> str:
    try:
        return datetime.fromtimestamp(
            os.path.getmtime(path), tz=timezone.utc
        ).isoformat()
    except OSError:
        return ""


def _classification_from_name(name: str) -> str:
    """Extract the classification suffix from an event folder name."""
    m = re.search(r"_pi_(.+?)(?:\.zip)?$", name)
    return m.group(1) if m else "unknown"


def _tail_lines(path: str, n: int) -> List[str]:
    """Return the last ``n`` lines of a (possibly large) file efficiently."""
    if not os.path.isfile(path):
        return []
    try:
        with open(path, "rb") as fh:
            fh.seek(0, os.SEEK_END)
            end = fh.tell()
            block = 8192
            data = b""
            newlines = 0
            pos = end
            while pos > 0 and newlines <= n:
                read = min(block, pos)
                pos -= read
                fh.seek(pos)
                chunk = fh.read(read)
                data = chunk + data
                newlines = data.count(b"\n")
            text = data.decode("utf-8", errors="replace")
            lines = text.splitlines()
            return lines[-n:]
    except OSError:
        return []


# --------------------------------------------------------------------------- #
# HTTP request handler
# --------------------------------------------------------------------------- #
def make_handler(server_logic: CollectorServer):
    """Create a BaseHTTPRequestHandler subclass bound to ``server_logic``."""

    class Handler(BaseHTTPRequestHandler):
        server_version = "netwatch-pi/1.0"
        # Silence default logging to stderr noise; can be re-enabled if desired.
        def log_message(self, fmt, *args):  # noqa: N802 (stdlib signature)
            pass

        # --- response helpers ---
        def _send_json(self, status: int, obj: Dict) -> None:
            payload = json.dumps(obj).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def _send_file(self, status: int, path: str, content_type: str,
                       filename: Optional[str] = None) -> None:
            """Stream a file from disk to the response in fixed-size chunks.

            Avoids holding a full multi-MB event archive in memory (as a naive
            ``fh.read()`` / in-memory ``BytesIO`` would), which matters both
            for the documented "streamed" download contract and because
            several concurrent downloads (the server is threaded) could
            otherwise multiply memory use enough to OOM a small Pi.
            """
            size = os.path.getsize(path)
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(size))
            if filename:
                self.send_header(
                    "Content-Disposition", f'attachment; filename="{filename}"'
                )
            self.end_headers()
            with open(path, "rb") as fh:
                shutil.copyfileobj(fh, self.wfile, length=STREAM_CHUNK_BYTES)

        def _authorized(self) -> bool:
            return server_logic.check_auth(self.headers.get("Authorization"))

        def _read_body(self, max_bytes: int) -> Optional[bytes]:
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                return None
            if length < 0 or length > max_bytes:
                return None
            return self.rfile.read(length) if length else b""

        # --- routing ---
        def do_GET(self):  # noqa: N802
            try:
                self._route_get()
            except Exception as exc:  # never crash the server thread
                self._safe_error(500, f"internal error: {exc}")

        def do_POST(self):  # noqa: N802
            try:
                self._route_post()
            except Exception as exc:
                self._safe_error(500, f"internal error: {exc}")

        def _safe_error(self, status: int, msg: str) -> None:
            try:
                self._send_json(status, {"error": msg})
            except Exception:
                pass

        def _route_get(self) -> None:
            parsed = urlparse(self.path)
            path = parsed.path.rstrip("/") or "/"
            query = parse_qs(parsed.query)

            if not self._authorized():
                self._send_json(401, {"error": "unauthorized"})
                return

            if path == "/health":
                self._send_json(200, server_logic.health())
                return
            if path == "/samples/latest":
                n = _first(query, "n") or str(SAMPLE_TAIL_DEFAULT)
                try:
                    n_int = int(n)
                except ValueError:
                    self._send_json(400, {"error": "n must be an integer"})
                    return
                self._send_json(200, server_logic.latest_samples(n_int))
                return
            if path == "/events":
                self._send_json(200, server_logic.list_events())
                return
            if path == "/collected":
                self._send_json(200, server_logic.list_collected())
                return

            # /events/{event_id} and /events/{event_id}/download
            m = re.match(r"^/events/([^/]+)(/download)?$", path)
            if m:
                event_id = m.group(1)
                if m.group(2):  # /download
                    result = server_logic.event_zip_path(event_id)
                    if result is None:
                        self._send_json(404, {"error": "event not found"})
                        return
                    zip_path, is_temp = result
                    try:
                        self._send_file(
                            200, zip_path, "application/zip",
                            filename=_sanitize_label(event_id) + ".zip",
                        )
                    finally:
                        if is_temp:
                            try:
                                os.remove(zip_path)
                            except OSError:
                                pass
                    return
                status, obj = server_logic.event_summary(event_id)
                self._send_json(status, obj)
                return

            self._send_json(404, {"error": "not found"})

        def _route_post(self) -> None:
            parsed = urlparse(self.path)
            path = parsed.path.rstrip("/") or "/"
            query = parse_qs(parsed.query)

            if not self._authorized():
                self._send_json(401, {"error": "unauthorized"})
                return

            content_type = (self.headers.get("Content-Type") or "").lower()

            if path == "/ingest/samples":
                body = self._read_body(MAX_JSON_BODY_BYTES)
                if body is None:
                    self._send_json(413, {"error": "body too large or invalid length"})
                    return
                status, obj = server_logic.ingest_samples(body)
                self._send_json(status, obj)
                return

            if path == "/ingest/events":
                if "zip" in content_type or "octet-stream" in content_type:
                    body = self._read_body(MAX_ZIP_BODY_BYTES)
                    if body is None:
                        self._send_json(413, {"error": "zip too large or invalid length"})
                        return
                    status, obj = server_logic.ingest_event_zip(body, query)
                    self._send_json(status, obj)
                    return
                body = self._read_body(MAX_JSON_BODY_BYTES)
                if body is None:
                    self._send_json(413, {"error": "body too large or invalid length"})
                    return
                status, obj = server_logic.ingest_event_json(body)
                self._send_json(status, obj)
                return

            self._send_json(404, {"error": "not found"})

    return Handler


def build_server(cfg) -> Tuple[ThreadingHTTPServer, CollectorServer]:
    """Construct (but do not start) the threaded HTTP server."""
    logic = CollectorServer(cfg)
    handler = make_handler(logic)
    bind = (cfg.collector["bind_host"], int(cfg.collector["bind_port"]))
    httpd = ThreadingHTTPServer(bind, handler)
    return httpd, logic


def serve_forever(cfg) -> None:
    """Blocking: run the collector HTTP server until interrupted."""
    httpd, _logic = build_server(cfg)
    addr = httpd.server_address
    print(f"[collector] listening on {addr[0]}:{addr[1]} "
          f"(auth={'on' if cfg.collector.get('auth_token') else 'off'})")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.shutdown()
        httpd.server_close()


def start_in_thread(cfg) -> Tuple[ThreadingHTTPServer, threading.Thread]:
    """Start the collector in a daemon thread (for ``run --serve``).

    Returns (httpd, thread). The thread is wrapped so that an unexpected failure
    in the server cannot take down the watchdog process — it logs and exits the
    thread only.
    """
    httpd, _logic = build_server(cfg)

    def _runner():
        try:
            httpd.serve_forever()
        except Exception as exc:  # isolate from the watchdog
            print(f"[collector] server thread stopped: {exc}")

    thread = threading.Thread(target=_runner, name="netwatch-collector", daemon=True)
    thread.start()
    addr = httpd.server_address
    print(f"[collector] background server on {addr[0]}:{addr[1]} "
          f"(auth={'on' if cfg.collector.get('auth_token') else 'off'})")
    return httpd, thread

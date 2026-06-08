"""Optional best-effort push of samples/events to a central Raspberry Pi collector.

Contract (kept deliberately dead-simple so the Pi side can mirror it exactly):

* ``POST {base_url}/ingest/samples``
    - Body: a single sample object, OR ``{"samples": [ ... ]}`` for a batch.
    - Every sample carries a ``host_label`` field.
* ``POST {base_url}/ingest/events``
    - Body: ``{"host_label": ..., "event_id": ..., "classification": ..., "summary": {...},
      "manifest": [...]}``.
    - Optionally a second request uploads the zipped event to the SAME path with
      ``Content-Type: application/zip`` and ``?host_label=...&event_id=...`` when the
      zip is under ``max_push_event_mb`` (see :meth:`push_event_zip`).
* Auth: when ``auth_token`` is set, send header ``Authorization: Bearer <token>``.
* All requests use a short timeout and swallow ALL exceptions. Pushing is never allowed
  to stall or crash polling. Failures are recorded into ``command_errors`` only.

Implemented with the stdlib ``urllib`` so there are no required third-party deps.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional

from .config import Config
from .runner import CommandErrorLog


class Collector:
    """Best-effort HTTP push client. No-op when disabled."""

    def __init__(self, cfg: Config) -> None:
        c = cfg.collector or {}
        self.enabled: bool = bool(c.get("enabled", False))
        self.base_url: str = str(c.get("base_url", "")).rstrip("/")
        self.auth_token: Optional[str] = c.get("auth_token")
        self.push_samples_enabled: bool = bool(c.get("push_samples", True))
        self.push_events_enabled: bool = bool(c.get("push_events", True))
        self.timeout: float = float(c.get("timeout_seconds", 3))
        self.batch_size: int = int(c.get("sample_batch_size", 10))
        self.max_push_event_mb: float = float(c.get("max_push_event_mb", 5))
        self.host_label: str = cfg.host_label

        # In-memory buffer so samples can be sent in small batches.
        self._sample_buffer: List[Dict[str, Any]] = []

    # --- low-level -----------------------------------------------------------
    def _headers(self, content_type: str) -> Dict[str, str]:
        headers = {"Content-Type": content_type}
        if self.auth_token:
            headers["Authorization"] = f"Bearer {self.auth_token}"
        return headers

    def _post_json(self, path: str, body: Dict[str, Any], error_log: CommandErrorLog) -> bool:
        """POST a JSON body. Returns True on 2xx, False otherwise. Never raises."""
        if not self.enabled or not self.base_url:
            return False
        url = f"{self.base_url}{path}"
        try:
            data = json.dumps(body).encode("utf-8")
            req = urllib.request.Request(
                url, data=data, headers=self._headers("application/json"), method="POST"
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return 200 <= resp.status < 300
        except Exception as exc:  # noqa: BLE001 - push is best-effort
            error_log.record_raw(f"collector POST {path}", f"{type(exc).__name__}: {exc}")
            return False

    def _post_bytes(
        self, path: str, raw: bytes, content_type: str, error_log: CommandErrorLog
    ) -> bool:
        if not self.enabled or not self.base_url:
            return False
        url = f"{self.base_url}{path}"
        try:
            req = urllib.request.Request(
                url, data=raw, headers=self._headers(content_type), method="POST"
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return 200 <= resp.status < 300
        except Exception as exc:  # noqa: BLE001
            error_log.record_raw(f"collector POST {path}", f"{type(exc).__name__}: {exc}")
            return False

    # --- samples -------------------------------------------------------------
    def push_sample(self, sample: Dict[str, Any], error_log: CommandErrorLog) -> None:
        """Buffer a sample and flush as a batch when the buffer is full."""
        if not (self.enabled and self.push_samples_enabled):
            return
        # Ensure host_label is present on each sample.
        sample = dict(sample)
        sample.setdefault("host_label", self.host_label)
        self._sample_buffer.append(sample)
        if len(self._sample_buffer) >= self.batch_size:
            self.flush_samples(error_log)

    def flush_samples(self, error_log: CommandErrorLog) -> None:
        """Send any buffered samples as ``{"samples": [...]}``. Drops buffer regardless."""
        if not (self.enabled and self.push_samples_enabled):
            self._sample_buffer.clear()
            return
        if not self._sample_buffer:
            return
        batch = self._sample_buffer
        self._sample_buffer = []
        self._post_json(
            "/ingest/samples",
            {"host_label": self.host_label, "samples": batch},
            error_log,
        )

    # --- events --------------------------------------------------------------
    def push_event(
        self,
        event_id: str,
        classification: str,
        summary: Dict[str, Any],
        manifest: List[str],
        error_log: CommandErrorLog,
    ) -> None:
        """Push an event summary + manifest (JSON)."""
        if not (self.enabled and self.push_events_enabled):
            return
        body = {
            "host_label": self.host_label,
            "event_id": event_id,
            "classification": classification,
            "summary": summary,
            "manifest": manifest,
        }
        self._post_json("/ingest/events", body, error_log)

    def push_event_zip(self, event_id: str, zip_path: str, error_log: CommandErrorLog) -> None:
        """Push the zipped event blob if under ``max_push_event_mb``.

        Sent to ``/ingest/events?host_label=...&event_id=...`` with ``Content-Type:
        application/zip`` so the Pi collector can optionally store the full evidence
        bundle. (The Pi host dispatches on content-type at the same ``/ingest/events``
        path used for the JSON summary.)
        """
        if not (self.enabled and self.push_events_enabled):
            return
        try:
            size_mb = os.path.getsize(zip_path) / (1024 * 1024)
        except OSError:
            return
        if size_mb > self.max_push_event_mb:
            error_log.record_raw(
                "collector push_event_zip",
                f"skipped: {size_mb:.1f}MB exceeds max_push_event_mb={self.max_push_event_mb}",
            )
            return
        try:
            with open(zip_path, "rb") as fh:
                raw = fh.read()
        except OSError as exc:
            error_log.record_raw("collector push_event_zip", f"read failed: {exc}")
            return
        query = urllib.parse.urlencode(
            {"host_label": self.host_label, "event_id": event_id}
        )
        self._post_bytes(
            f"/ingest/events?{query}", raw, "application/zip", error_log
        )

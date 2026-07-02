"""Regression tests for the netwatch-pi collector trust boundary (stdlib unittest).

Covers the ingest-side defenses that protect the Pi from a hostile / buggy
push client on the LAN:
  * ``_sanitize_label`` — path-traversal and separator stripping.
  * ``CollectorServer.check_auth`` — bearer-token gate, including the
    non-ASCII header case that must return False (not raise -> 500).
  * ``ingest_event_zip`` — rejects a non-zip body and an oversized body.

Run with:  python -m unittest discover -s netwatch-pi/tests
       or:  python -m pytest netwatch-pi/tests
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from netwatch import collector as collector_mod  # noqa: E402
from netwatch.collector import CollectorServer, _sanitize_label  # noqa: E402
from netwatch.config import Config, default_config_dict  # noqa: E402


class TestSanitizeLabel(unittest.TestCase):
    def test_plain_label_kept(self):
        self.assertEqual(_sanitize_label("gaming-desktop"), "gaming-desktop")

    def test_traversal_neutralized(self):
        self.assertNotIn("/", _sanitize_label("../../etc/passwd"))
        self.assertNotIn("\\", _sanitize_label("..\\..\\windows"))
        # Pure dot-dot collapses to the fallback.
        self.assertEqual(_sanitize_label(".."), "unknown-host")
        self.assertEqual(_sanitize_label("."), "unknown-host")

    def test_separators_replaced(self):
        cleaned = _sanitize_label("a/b\\c")
        self.assertNotIn("/", cleaned)
        self.assertNotIn("\\", cleaned)

    def test_empty_uses_fallback(self):
        self.assertEqual(_sanitize_label("", fallback="fb"), "fb")
        self.assertEqual(_sanitize_label(None, fallback="fb"), "fb")

    def test_length_capped(self):
        self.assertLessEqual(len(_sanitize_label("x" * 500)), 128)


def _cfg(tmpdir: str, auth_token=None) -> Config:
    raw = default_config_dict()
    raw["output_dir"] = tmpdir
    raw["jsonl_log_path"] = os.path.join(tmpdir, "netwatch-pi.jsonl")
    raw["collector"]["incoming_dir"] = os.path.join(tmpdir, "incoming")
    raw["collector"]["auth_token"] = auth_token
    return Config(raw, path=None)


class TestCheckAuth(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self._tmp.cleanup()

    def test_open_server_allows_all(self):
        srv = CollectorServer(_cfg(self._tmp.name, auth_token=None))
        self.assertTrue(srv.check_auth(None))
        self.assertTrue(srv.check_auth("anything"))

    def test_token_required_and_matched(self):
        srv = CollectorServer(_cfg(self._tmp.name, auth_token="s3cret"))
        self.assertFalse(srv.check_auth(None))
        self.assertFalse(srv.check_auth("Bearer wrong"))
        self.assertTrue(srv.check_auth("Bearer s3cret"))

    def test_non_ascii_header_returns_false_not_raises(self):
        # A malformed / non-ASCII Authorization header must NOT bubble up as a
        # 500 via the handler's catch-all — it should just fail auth.
        srv = CollectorServer(_cfg(self._tmp.name, auth_token="s3cret"))
        self.assertFalse(srv.check_auth("Bearer \udce9\udcffbad"))


class TestIngestZip(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.srv = CollectorServer(_cfg(self._tmp.name, auth_token=None))

    def tearDown(self):
        self._tmp.cleanup()

    def test_rejects_non_zip_body(self):
        status, obj = self.srv.ingest_event_zip(
            b"not a zip", {"host_label": ["h"], "event_id": ["e1"]}
        )
        self.assertEqual(status, 400)

    def test_requires_event_id(self):
        status, obj = self.srv.ingest_event_zip(b"PK\x03\x04", {"host_label": ["h"]})
        self.assertEqual(status, 400)

    def test_rejects_oversized_body(self):
        big = b"x" * (collector_mod.MAX_ZIP_BODY_BYTES + 1)
        status, obj = self.srv.ingest_event_zip(
            big, {"host_label": ["h"], "event_id": ["e1"]}
        )
        self.assertEqual(status, 413)


if __name__ == "__main__":
    unittest.main()

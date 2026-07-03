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

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from netwatch import collector as collector_mod  # noqa: E402
from netwatch.collector import (  # noqa: E402
    CollectorServer,
    _read_body_bounded,
    _sanitize_label,
)
from netwatch.config import Config, default_config_dict  # noqa: E402


class _TricklingReader:
    """Fake rfile whose read1 returns a bounded chunk per call (simulates trickle)."""

    def __init__(self, total: bytes, per_call: int):
        self._buf = total
        self._per_call = per_call
        self.calls = 0

    def read1(self, n):
        self.calls += 1
        take = min(n, self._per_call, len(self._buf))
        chunk, self._buf = self._buf[:take], self._buf[take:]
        return chunk


class TestReadBodyBounded(unittest.TestCase):
    def test_happy_path_reads_full_body(self):
        r = _TricklingReader(b"hello world", per_call=4)
        self.assertEqual(_read_body_bounded(r, 11, 1024, 30), b"hello world")

    def test_zero_length_returns_empty(self):
        self.assertEqual(_read_body_bounded(_TricklingReader(b"", 1), 0, 1024, 30), b"")

    def test_over_max_rejected(self):
        self.assertIsNone(_read_body_bounded(_TricklingReader(b"x", 1), 5, 4, 30))

    def test_early_close_returns_none(self):
        # Reader runs out of bytes before the declared length -> incomplete -> None.
        self.assertIsNone(_read_body_bounded(_TricklingReader(b"abc", 1), 10, 1024, 30))

    def test_deadline_abort_on_slow_trickle(self):
        # Fake clock jumps past the deadline: the total-read deadline must abort
        # even though the reader still has data (slowloris), so the handler thread
        # is not pinned indefinitely by a byte-per-<timeout> trickle.
        ticks = iter([0.0, 0.0, 100.0, 200.0, 300.0, 400.0])
        r = _TricklingReader(b"x" * 1000, per_call=1)
        self.assertIsNone(_read_body_bounded(r, 1000, 10_000, 30, now=lambda: next(ticks)))

    def test_completing_chunk_arriving_late_is_rejected(self):
        # The final chunk completes the declared 2-byte body, but the post-read
        # clock is already past the deadline -> must be REJECTED, not accepted.
        # setup=0 -> deadline=30; iter1 top=0, after-read=10; iter2 top=10,
        # after-read=40 (>30) -> None.
        ticks = iter([0.0, 0.0, 10.0, 10.0, 40.0])
        r = _TricklingReader(b"ab", per_call=1)
        self.assertIsNone(_read_body_bounded(r, 2, 1024, 30, now=lambda: next(ticks)))


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


def _cfg(tmpdir: str, auth_token=False) -> Config:
    """Test config. NOTE: auth_token defaults to False (explicit open mode) so
    handler-logic tests don't exercise token auto-generation; pass None to test
    the secure default."""
    raw = default_config_dict()
    raw["output_dir"] = tmpdir
    raw["jsonl_log_path"] = os.path.join(tmpdir, "netwatch-pi.jsonl")
    raw["collector"]["incoming_dir"] = os.path.join(tmpdir, "incoming")
    raw["collector"]["auth_token"] = auth_token
    raw["collector"]["token_file"] = os.path.join(tmpdir, "collector.token")
    return Config(raw, path=None)


class TestCheckAuth(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self._tmp.cleanup()

    def test_explicit_false_disables_auth(self):
        srv = CollectorServer(_cfg(self._tmp.name, auth_token=False))
        self.assertEqual(srv.auth_mode, "open")
        self.assertTrue(srv.check_auth(None))
        self.assertTrue(srv.check_auth("anything"))
        self.assertIn("auth=OFF", srv.auth_describe())

    def test_null_default_auto_generates_and_requires_token(self):
        # The secure default: auth_token null -> generate + persist + require.
        srv = CollectorServer(_cfg(self._tmp.name, auth_token=None))
        self.assertEqual(srv.auth_mode, "generated")
        self.assertTrue(os.path.isfile(srv.token_file))
        with open(srv.token_file, "r", encoding="utf-8") as fh:
            token = fh.read().strip()
        self.assertGreaterEqual(len(token), 32)
        self.assertFalse(srv.check_auth(None))
        self.assertFalse(srv.check_auth("Bearer wrong"))
        self.assertTrue(srv.check_auth(f"Bearer {token}"))
        # Owner-only permissions on the persisted token.
        if os.name == "posix":
            self.assertEqual(os.stat(srv.token_file).st_mode & 0o777, 0o600)

    @unittest.skipUnless(os.name == "posix", "posix permissions")
    def test_preexisting_loose_perms_tightened_on_write(self):
        # An EMPTY token file left behind with loose permissions must not stay
        # world-readable once the token is written into it (os.open's mode only
        # applies on creation; fchmod covers the pre-existing case).
        cfg = _cfg(self._tmp.name, auth_token=None)
        token_path = cfg.collector["token_file"]
        with open(token_path, "w", encoding="utf-8"):
            pass
        os.chmod(token_path, 0o644)
        srv = CollectorServer(cfg)
        self.assertEqual(srv.auth_mode, "generated")
        self.assertEqual(os.stat(token_path).st_mode & 0o777, 0o600)

    def test_generated_token_is_stable_across_restarts(self):
        cfg = _cfg(self._tmp.name, auth_token=None)
        first = CollectorServer(cfg).auth_token
        second = CollectorServer(cfg).auth_token
        self.assertEqual(first, second)

    def test_token_required_and_matched(self):
        srv = CollectorServer(_cfg(self._tmp.name, auth_token="s3cret"))
        self.assertEqual(srv.auth_mode, "configured")
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
        self.srv = CollectorServer(_cfg(self._tmp.name))

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


class TestIngestSamples(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.srv = CollectorServer(_cfg(self._tmp.name))

    def tearDown(self):
        self._tmp.cleanup()

    def test_batch_written_to_per_host_jsonl(self):
        body = json.dumps(
            {"samples": [{"host_label": "win", "v": i} for i in range(25)]}
        ).encode("utf-8")
        status, obj = self.srv.ingest_samples(body)
        self.assertEqual(status, 200)
        self.assertEqual(obj["written"], 25)
        path = os.path.join(self.srv.incoming_dir, "win", "samples.jsonl")
        with open(path, "r", encoding="utf-8") as fh:
            lines = [json.loads(l) for l in fh if l.strip()]
        self.assertEqual(len(lines), 25)
        self.assertEqual(lines[0]["host_label"], "win")

    def test_rejects_over_sample_count_cap(self):
        # An 8 MB body can carry ~100k tiny samples; the per-request cap must
        # bound the work a single request can force on the handler thread.
        n = collector_mod.MAX_SAMPLES_PER_REQUEST + 1
        body = json.dumps({"samples": [{"v": 1}] * n}).encode("utf-8")
        status, obj = self.srv.ingest_samples(body)
        self.assertEqual(status, 413)
        # Nothing written for the rejected request.
        self.assertFalse(
            os.path.isfile(
                os.path.join(self.srv.incoming_dir, "unknown-host", "samples.jsonl")
            )
        )

    def test_cap_boundary_accepted(self):
        n = collector_mod.MAX_SAMPLES_PER_REQUEST
        body = json.dumps({"samples": [{"host_label": "win", "v": 1}] * n}).encode("utf-8")
        status, obj = self.srv.ingest_samples(body)
        self.assertEqual(status, 200)
        self.assertEqual(obj["written"], n)


if __name__ == "__main__":
    unittest.main()

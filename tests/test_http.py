"""Security tests for the HTTP layer, against a local test server.

Covers: scheme allowlist, same-host redirect follow, cross-host redirect
rejection (final, no fallback), TLS-downgrade rejection, response size cap,
4xx semantics.
"""

import http.server  # noqa: stdlib; the tool's module is aliased avhttp
import os
import tempfile
import threading
import unittest
from types import SimpleNamespace
from unittest import mock

from aurvet import http as avhttp


class _Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        base = self.server.baseurl
        if self.path == "/ok":
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")
        elif self.path == "/redirect-same":
            self.send_response(302)
            self.send_header("Location", base + "/ok")
            self.end_headers()
        elif self.path == "/redirect-cross":
            self.send_response(302)
            self.send_header("Location", "http://example.invalid/ok")
            self.end_headers()
        elif self.path == "/big":
            # 10 MiB streamed in 1 MiB chunks, no Content-Length
            self.send_response(200)
            self.end_headers()
            try:
                for _ in range(10):
                    self.wfile.write(b"A" * (1024 * 1024))
            except OSError:
                pass  # client aborted (size-cap test) mid-stream
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()


class PolicyUnitTests(unittest.TestCase):
    """Redirect-policy checks without any network: the policy decision
    happens before the super().open follow, so a fake request object is
    enough and the disallowed cases raise before touching a parent."""

    def _h(self):
        return avhttp._StrictRedirectHandler()

    def _req(self, url):
        return SimpleNamespace(full_url=url)

    def test_relative_location_rejected(self):
        with self.assertRaises(avhttp.HttpError) as cm:
            self._h()._validated(self._req("https://aur.example/cgit/x"), None,
                                 302, "Found", {"Location": "/elsewhere"})
        self.assertTrue(cm.exception.final)

    def test_foreign_scheme_rejected(self):
        with self.assertRaises(avhttp.HttpError) as cm:
            self._h()._validated(self._req("https://aur.example/x"), None, 302,
                                 "Found", {"Location": "file:///etc/passwd"})
        self.assertTrue(cm.exception.final)
        self.assertIn("disallowed scheme", str(cm.exception))

    def test_cross_host_rejected(self):
        with self.assertRaises(avhttp.HttpError) as cm:
            self._h()._validated(self._req("https://aur.example/x"), None, 302,
                                 "Found", {"Location": "https://evil.example/x"})
        self.assertTrue(cm.exception.final)
        self.assertIn("cross-host", str(cm.exception))

    def test_tls_downgrade_rejected(self):
        with self.assertRaises(avhttp.HttpError) as cm:
            self._h()._validated(self._req("https://aur.example/x"), None, 301,
                                 "Moved", {"Location": "http://aur.example/x"})
        self.assertTrue(cm.exception.final)
        self.assertIn("downgrade", str(cm.exception))

    def test_missing_location_rejected(self):
        with self.assertRaises(avhttp.HttpError) as cm:
            self._h()._validated(self._req("https://aur.example/x"), None, 303,
                                 "See Other", {})
        self.assertTrue(cm.exception.final)

    def test_fetch_rejects_non_http_schemes(self):
        for url in ("file:///etc/passwd", "ftp://example.invalid/x",
                    "not a url", "gopher://x/y"):
            with self.assertRaises(avhttp.HttpError) as cm:
                avhttp.fetch(url)
            self.assertTrue(cm.exception.final)


class LiveServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        cls.server.baseurl = f"http://127.0.0.1:{cls.server.server_address[1]}"
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        # isolate cache, build the opener with a clean (proxy-free) env,
        # and restore the previous opener afterwards
        self.tmp = tempfile.TemporaryDirectory()
        self.p_cache = mock.patch.object(avhttp, "cache_dir",
                                         lambda: self.tmp.name)
        self.p_cache.start()
        self.p_env = mock.patch.dict(os.environ, {
            k: "" for k in ("http_proxy", "HTTP_PROXY", "https_proxy",
                            "HTTPS_PROXY")
        }, clear=False)
        self.p_env.start()
        self._saved_opener = avhttp._OPENER
        avhttp._OPENER = None  # fresh opener honors the clean env

    def tearDown(self):
        self.p_env.stop()
        self.p_cache.stop()
        self.tmp.cleanup()
        avhttp._OPENER = self._saved_opener

    def test_same_host_redirect_followed(self):
        data = avhttp.fetch(f"{self.server.baseurl}/redirect-same", retries=0)
        self.assertEqual(data, b"ok")

    def test_cross_host_redirect_rejected_no_fallback(self):
        with self.assertRaises(avhttp.HttpError) as cm:
            avhttp.fetch(f"{self.server.baseurl}/redirect-cross", retries=0)
        self.assertTrue(cm.exception.final)
        self.assertIn("cross-host", str(cm.exception))

    def test_size_cap_enforced(self):
        with mock.patch.object(avhttp, "MAX_RESPONSE_BYTES", 100 * 1024):
            with self.assertRaises(avhttp.HttpError) as cm:
                avhttp.fetch(f"{self.server.baseurl}/big", retries=0)
        self.assertIn("exceeds", str(cm.exception))

    def test_404_carries_status_and_no_retry(self):
        import time
        t0 = time.monotonic()
        with self.assertRaises(avhttp.HttpError) as cm:
            avhttp.fetch(f"{self.server.baseurl}/missing", retries=0)
        self.assertEqual(cm.exception.status, 404)
        self.assertLess(time.monotonic() - t0, 5)  # no backoff sleep


if __name__ == "__main__":
    unittest.main()

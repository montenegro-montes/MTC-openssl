"""Tests for the read-only relying-party server state view."""

import tempfile
import unittest
from pathlib import Path

from rp_server import RPServer
from rp_state import RPStateStore
from trusted_subtrees import TrustedSubtree, encode_trusted_subtrees


class RPServerTest(unittest.TestCase):

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(
            prefix="mtc-rp-server-test-"
        )
        self.state = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def test_empty_state(self):
        server = RPServer(self.state)

        self.assertIsNone(server.current())
        self.assertIsNone(server.metadata())
        self.assertIsNone(server.trusted_subtrees())

    def test_serves_current_generation(self):
        store = RPStateStore(self.state)

        checkpoint = {
            "log_number": 1,
            "tree_size": 16,
            "hash": "11" * 32,
        }

        mts1 = encode_trusted_subtrees([
            TrustedSubtree(
                log_number=1,
                start=0,
                end=16,
                hash=bytes.fromhex("22" * 32),
            ),
        ])

        store.publish(
            checkpoint,
            mts1,
            retained_landmark=1,
        )

        server = RPServer(self.state)

        current = server.current()
        self.assertEqual(current["checkpoint"], checkpoint)
        self.assertEqual(current["trusted_subtrees"], mts1)
        self.assertEqual(current["retained_landmark"], 1)

        self.assertEqual(
            server.metadata(),
            {
                "version": 1,
                "checkpoint": checkpoint,
                "retained_landmark": 1,
            },
        )

        self.assertEqual(server.trusted_subtrees(), mts1)


class RPServerHTTPTest(unittest.TestCase):

    def setUp(self):
        import threading
        from http.server import ThreadingHTTPServer

        from rp_server import make_handler

        self.temporary = tempfile.TemporaryDirectory(
            prefix="mtc-rp-server-http-test-"
        )
        self.state = Path(self.temporary.name)
        self.rp_server = RPServer(self.state)

        self.httpd = ThreadingHTTPServer(
            ("127.0.0.1", 0),
            make_handler(self.rp_server),
        )
        self.thread = threading.Thread(
            target=self.httpd.serve_forever,
            daemon=True,
        )
        self.thread.start()

        host, port = self.httpd.server_address
        self.base_url = f"http://{host}:{port}"

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join()
        self.temporary.cleanup()

    def request(self, path, method="GET"):
        from urllib.error import HTTPError
        from urllib.request import Request, urlopen

        request = Request(
            self.base_url + path,
            method=method,
        )
        try:
            with urlopen(request, timeout=2) as response:
                return (
                    response.status,
                    response.headers.get_content_type(),
                    response.read(),
                )
        except HTTPError as exc:
            return (
                exc.code,
                exc.headers.get_content_type(),
                exc.read(),
            )

    def publish(self):
        checkpoint = {
            "log_number": 1,
            "tree_size": 16,
            "hash": "11" * 32,
        }

        mts1 = encode_trusted_subtrees([
            TrustedSubtree(
                log_number=1,
                start=0,
                end=16,
                hash=bytes.fromhex("22" * 32),
            ),
        ])

        RPStateStore(self.state).publish(
            checkpoint,
            mts1,
            retained_landmark=1,
        )

        return checkpoint, mts1

    def test_health_empty(self):
        status, content_type, body = self.request("/health")

        self.assertEqual(status, 200)
        self.assertEqual(content_type, "application/json")
        self.assertEqual(
            __import__("json").loads(body),
            {
                "state": "empty",
                "status": "ok",
            },
        )

    def test_metadata_and_trusted_subtrees(self):
        checkpoint, mts1 = self.publish()

        status, content_type, body = self.request("/metadata")
        self.assertEqual(status, 200)
        self.assertEqual(content_type, "application/json")
        self.assertEqual(
            __import__("json").loads(body),
            {
                "version": 1,
                "checkpoint": checkpoint,
                "retained_landmark": 1,
            },
        )

        status, content_type, body = self.request("/trusted-subtrees")
        self.assertEqual(status, 200)
        self.assertEqual(content_type, "application/octet-stream")
        self.assertEqual(body, mts1)

    def test_missing_state_returns_404(self):
        for path in ("/metadata", "/trusted-subtrees"):
            status, _, _ = self.request(path)
            self.assertEqual(status, 404)

    def test_unknown_path_returns_404(self):
        status, _, _ = self.request("/unknown")
        self.assertEqual(status, 404)

    def test_write_methods_are_rejected(self):
        for method in ("POST", "PUT", "DELETE"):
            status, _, _ = self.request("/trusted-subtrees", method=method)
            self.assertEqual(status, 405)

if __name__ == "__main__":
    unittest.main()

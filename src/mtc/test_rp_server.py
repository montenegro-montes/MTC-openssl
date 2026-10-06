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


    def test_publish_is_idempotent(self):
        server = RPServer(self.state)

        checkpoint = {
            "log_number": 1,
            "tree_size": 16,
            "hash": "11" * 32,
        }
        mts1 = encode_trusted_subtrees([])

        first = server.publish(checkpoint, mts1)
        second = server.publish(checkpoint, mts1)

        self.assertEqual(
            first["checkpoint"],
            second["checkpoint"],
        )
        self.assertEqual(
            first["trusted_subtrees"],
            second["trusted_subtrees"],
        )

    def test_publish_rejects_rollback(self):
        server = RPServer(self.state)
        mts1 = encode_trusted_subtrees([])

        server.publish(
            {
                "log_number": 1,
                "tree_size": 16,
                "hash": "11" * 32,
            },
            mts1,
        )

        with self.assertRaisesRegex(ValueError, "rollback"):
            server.publish(
                {
                    "log_number": 1,
                    "tree_size": 8,
                    "hash": "22" * 32,
                },
                mts1,
            )

        self.assertEqual(
            server.current()["checkpoint"]["tree_size"],
            16,
        )

    def test_publish_rejects_same_size_equivocation(self):
        server = RPServer(self.state)
        mts1 = encode_trusted_subtrees([])

        server.publish(
            {
                "log_number": 1,
                "tree_size": 16,
                "hash": "11" * 32,
            },
            mts1,
        )

        with self.assertRaisesRegex(ValueError, "same tree size"):
            server.publish(
                {
                    "log_number": 1,
                    "tree_size": 16,
                    "hash": "22" * 32,
                },
                mts1,
            )

        self.assertEqual(
            server.current()["checkpoint"]["hash"],
            "11" * 32,
        )

    def test_publish_rejects_log_change(self):
        server = RPServer(self.state)

        server.publish(
            {
                "log_number": 1,
                "tree_size": 16,
                "hash": "11" * 32,
            },
            encode_trusted_subtrees([]),
        )

        with self.assertRaisesRegex(ValueError, "issuance log"):
            server.publish(
                {
                    "log_number": 2,
                    "tree_size": 16,
                    "hash": "22" * 32,
                },
                encode_trusted_subtrees([]),
            )

        self.assertEqual(
            server.current()["checkpoint"]["log_number"],
            1,
        )

    def test_publish_accepts_forward_state(self):
        server = RPServer(self.state)
        mts1 = encode_trusted_subtrees([])

        server.publish(
            {
                "log_number": 1,
                "tree_size": 16,
                "hash": "11" * 32,
            },
            mts1,
        )

        published = server.publish(
            {
                "log_number": 1,
                "tree_size": 32,
                "hash": "22" * 32,
            },
            mts1,
        )

        self.assertEqual(
            published["checkpoint"]["tree_size"],
            32,
        )


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

    def put_state(self, checkpoint, mts1, retained_landmark=None):
        from urllib.error import HTTPError
        from urllib.request import Request, urlopen

        headers = {
            "Content-Type": "application/octet-stream",
            "MTC-RP-Version": "1",
            "MTC-Log-Number": str(checkpoint["log_number"]),
            "MTC-Tree-Size": str(checkpoint["tree_size"]),
            "MTC-Checkpoint-Hash": checkpoint["hash"],
            "MTC-Retained-Landmark": (
                "none"
                if retained_landmark is None
                else str(retained_landmark)
            ),
        }

        request = Request(
            self.base_url + "/internal/state",
            data=mts1,
            headers=headers,
            method="PUT",
        )

        try:
            with urlopen(request, timeout=2) as response:
                return response.status
        except HTTPError as exc:
            return exc.code

    def test_internal_put_publishes_state(self):
        checkpoint = {
            "log_number": 1,
            "tree_size": 16,
            "hash": "11" * 32,
        }
        mts1 = encode_trusted_subtrees([])

        status = self.put_state(
            checkpoint,
            mts1,
            retained_landmark=1,
        )

        self.assertEqual(status, 204)

        current = self.rp_server.current()
        self.assertEqual(current["checkpoint"], checkpoint)
        self.assertEqual(current["trusted_subtrees"], mts1)
        self.assertEqual(current["retained_landmark"], 1)

    def test_internal_put_rejects_rollback(self):
        mts1 = encode_trusted_subtrees([])

        self.assertEqual(
            self.put_state(
                {
                    "log_number": 1,
                    "tree_size": 16,
                    "hash": "11" * 32,
                },
                mts1,
            ),
            204,
        )

        self.assertEqual(
            self.put_state(
                {
                    "log_number": 1,
                    "tree_size": 8,
                    "hash": "22" * 32,
                },
                mts1,
            ),
            409,
        )

        self.assertEqual(
            self.rp_server.current()["checkpoint"]["tree_size"],
            16,
        )


    def test_internal_put_rejects_same_size_equivocation(self):
        mts1 = encode_trusted_subtrees([])

        self.assertEqual(
            self.put_state(
                {
                    "log_number": 1,
                    "tree_size": 16,
                    "hash": "11" * 32,
                },
                mts1,
            ),
            204,
        )

        self.assertEqual(
            self.put_state(
                {
                    "log_number": 1,
                    "tree_size": 16,
                    "hash": "22" * 32,
                },
                mts1,
            ),
            409,
        )

        self.assertEqual(
            self.rp_server.current()["checkpoint"]["hash"],
            "11" * 32,
        )

    def test_internal_put_rejects_log_change(self):
        mts1 = encode_trusted_subtrees([])

        self.assertEqual(
            self.put_state(
                {
                    "log_number": 1,
                    "tree_size": 16,
                    "hash": "11" * 32,
                },
                mts1,
            ),
            204,
        )

        self.assertEqual(
            self.put_state(
                {
                    "log_number": 2,
                    "tree_size": 32,
                    "hash": "22" * 32,
                },
                mts1,
            ),
            409,
        )

        self.assertEqual(
            self.rp_server.current()["checkpoint"]["log_number"],
            1,
        )

    def test_internal_put_rejects_malformed_mts1(self):
        checkpoint = {
            "log_number": 1,
            "tree_size": 16,
            "hash": "11" * 32,
        }

        self.assertEqual(
            self.put_state(
                checkpoint,
                b"not-an-mts1",
            ),
            409,
        )

        self.assertIsNone(self.rp_server.current())


    def test_internal_put_requires_protocol_version(self):
        from urllib.error import HTTPError
        from urllib.request import Request, urlopen

        request = Request(
            self.base_url + "/internal/state",
            data=encode_trusted_subtrees([]),
            headers={
                "Content-Type": "application/octet-stream",
                "MTC-Log-Number": "1",
                "MTC-Tree-Size": "16",
                "MTC-Checkpoint-Hash": "11" * 32,
            },
            method="PUT",
        )

        with self.assertRaises(HTTPError) as raised:
            urlopen(request, timeout=2)

        self.assertEqual(raised.exception.code, 400)
        self.assertIsNone(self.rp_server.current())


if __name__ == "__main__":
    unittest.main()

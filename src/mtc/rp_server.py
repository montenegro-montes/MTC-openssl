"""Read-only HTTP service for validated relying-party state."""

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from rp_state import RPStateStore


class RPServer:
    """Read-only view of the currently published RP generation."""

    def __init__(self, state_directory):
        self.store = RPStateStore(state_directory)

    def current(self):
        return self.store.load_current()

    def metadata(self):
        current = self.current()
        if current is None:
            return None

        return {
            "version": 1,
            "checkpoint": current["checkpoint"],
            "retained_landmark": current["retained_landmark"],
        }

    def trusted_subtrees(self):
        current = self.current()
        if current is None:
            return None
        return current["trusted_subtrees"]

    def publish(self, checkpoint, trusted_subtrees, retained_landmark=None):
        """Publish state without allowing rollback or cross-log replacement."""
        current = self.current()

        if current is not None:
            previous = current["checkpoint"]

            if checkpoint["log_number"] != previous["log_number"]:
                raise ValueError("RP publication changes issuance log")

            if checkpoint["tree_size"] < previous["tree_size"]:
                raise ValueError("RP publication rollback")

            if (checkpoint["tree_size"] == previous["tree_size"]
                    and checkpoint["hash"] != previous["hash"]):
                raise ValueError(
                    "RP publication changes hash at same tree size")

        return self.store.publish(
            checkpoint,
            trusted_subtrees,
            retained_landmark,
        )


def make_handler(server):
    class Handler(BaseHTTPRequestHandler):
        def _send(self, status, content_type, body=b""):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if body:
                self.wfile.write(body)

        def do_GET(self):
            path = urlsplit(self.path).path

            try:
                if path == "/health":
                    current = server.current()
                    body = json.dumps(
                        {
                            "status": "ok",
                            "state": (
                                "ready" if current is not None else "empty"
                            ),
                        },
                        sort_keys=True,
                        separators=(",", ":"),
                    ).encode("ascii") + b"\n"
                    self._send(200, "application/json", body)
                    return

                if path == "/metadata":
                    metadata = server.metadata()
                    if metadata is None:
                        self._send(404, "application/json")
                        return
                    body = json.dumps(
                        metadata,
                        sort_keys=True,
                        separators=(",", ":"),
                    ).encode("ascii") + b"\n"
                    self._send(200, "application/json", body)
                    return

                if path == "/trusted-subtrees":
                    mts1 = server.trusted_subtrees()
                    if mts1 is None:
                        self._send(404, "application/octet-stream")
                        return
                    self._send(200, "application/octet-stream", mts1)
                    return

                self._send(404, "text/plain")

            except (OSError, ValueError):
                self._send(500, "text/plain")

        def do_POST(self):
            self._send(405, "text/plain")

        def do_PUT(self):
            path = urlsplit(self.path).path

            if path != "/internal/state":
                self._send(405, "text/plain")
                return

            try:
                if self.headers.get_content_type() != "application/octet-stream":
                    self._send(415, "text/plain")
                    return

                if self.headers.get("MTC-RP-Version") != "1":
                    self._send(400, "text/plain")
                    return

                content_length = self.headers.get("Content-Length")
                if content_length is None:
                    self._send(411, "text/plain")
                    return

                try:
                    content_length = int(content_length)
                except ValueError:
                    self._send(400, "text/plain")
                    return

                if content_length < 0 or content_length > 16 * 1024 * 1024:
                    self._send(413, "text/plain")
                    return

                try:
                    log_number = int(self.headers["MTC-Log-Number"])
                    tree_size = int(self.headers["MTC-Tree-Size"])
                    checkpoint_hash = self.headers["MTC-Checkpoint-Hash"]
                except (KeyError, ValueError):
                    self._send(400, "text/plain")
                    return

                retained_header = self.headers.get("MTC-Retained-Landmark")
                if retained_header is None or retained_header == "none":
                    retained_landmark = None
                else:
                    try:
                        retained_landmark = int(retained_header)
                    except ValueError:
                        self._send(400, "text/plain")
                        return

                body = self.rfile.read(content_length)
                if len(body) != content_length:
                    self._send(400, "text/plain")
                    return

                checkpoint = {
                    "log_number": log_number,
                    "tree_size": tree_size,
                    "hash": checkpoint_hash,
                }

                server.publish(
                    checkpoint,
                    body,
                    retained_landmark,
                )

                self._send(204, "text/plain")

            except ValueError:
                self._send(409, "text/plain")
            except OSError:
                self._send(500, "text/plain")

        def do_DELETE(self):
            self._send(405, "text/plain")

        def log_message(self, format, *args):
            pass

    return Handler


def serve(state_directory, host, port):
    rp_server = RPServer(state_directory)
    httpd = ThreadingHTTPServer(
        (host, port),
        make_handler(rp_server),
    )
    httpd.serve_forever()


def main():
    parser = argparse.ArgumentParser(
        description="Serve validated MTC relying-party state read-only."
    )
    parser.add_argument("--state", required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8082)
    args = parser.parse_args()

    if not 0 <= args.port <= 65535:
        parser.error("--port must be between 0 and 65535")

    serve(args.state, args.host, args.port)


if __name__ == "__main__":
    main()

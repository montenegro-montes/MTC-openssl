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
            self._send(405, "text/plain")

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

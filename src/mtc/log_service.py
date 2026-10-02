"""Experimental synchronous HTTP access to LocalLog; all roots are unsigned."""
import argparse
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import stat
import time
from urllib.parse import parse_qs, urlsplit

from local_log import LocalLog


def number(text):
    if not text or not text.isascii() or not text.isdecimal() or len(text) > 15:
        raise ValueError('Expected a nonnegative decimal integer')
    return int(text)


class LogServer(HTTPServer):
    def __init__(self, address, directory, snapshot=None, read_only=False):
        self.log = LocalLog(directory)
        self.snapshot = None if snapshot is None else Path(snapshot)
        if type(read_only) is not bool:
            raise ValueError('read_only must be boolean')
        self.read_only = read_only
        if self.snapshot is not None:
            if self.snapshot.is_symlink() or not self.snapshot.is_file():
                raise ValueError('Snapshot must be a regular file')
        super().__init__(address, LogHandler)


class LogHandler(BaseHTTPRequestHandler):
    timeout = 2  # Seconds of socket inactivity; POST bodies also have a total deadline.

    def setup(self):
        super().setup()
        self.connection.settimeout(self.timeout)

    def handle(self):
        try:super().handle()
        except OSError:
            # Peer disconnected or timed out; a response may no longer be possible.
            self.close_connection = True

    def log_message(self, *args):
        pass

    def reply(self, status, value, binary=False, allow=None):
        body = value if binary else (json.dumps(value, sort_keys=True)+'\n').encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/octet-stream' if binary else 'application/json')
        self.send_header('Content-Length', str(len(body)))
        if allow:self.send_header('Allow', allow)
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(body)

    def send_error(self, code, message=None, explain=None):
        # Includes HTTP parser errors and unsupported methods; no tracebacks.
        if code == 501:
            try:allow = self.allowed(urlsplit(self.path).path)
            except ValueError:
                self.reply(400, {'error': 'Malformed request target'}); return
            if allow:self.reply(405, {'error': 'Method not allowed'}, allow=allow)
            else:self.reply(404, {'error': 'Unknown endpoint'})
            return
        self.reply(code, {'error': self.responses.get(code, ('Request failed',))[0]})

    @staticmethod
    def allowed(path):
        if path == '/entries':return 'POST'
        if path in ('/checkpoint', '/proof/consistency', '/proof/subtree', '/snapshot') or path.startswith(('/entries/', '/proof/inclusion/')):
            return 'GET'
        return None

    def do_GET(self):
        self.dispatch(False)

    def do_POST(self):
        self.dispatch(True)

    def dispatch(self, post):
        try:
            parsed = urlsplit(self.path)
            query = parse_qs(parsed.query, keep_blank_values=True, strict_parsing=True)
            path = parsed.path
            allow = self.allowed(path)
            if allow and self.command != allow:
                self.reply(405, {'error': 'Method not allowed'}, allow=allow); return
            if post:
                if path != '/entries':
                    self.reply(404, {'error': 'Unknown endpoint'}); return
                if self.server.read_only:
                    self.reply(405, {'error': 'Read-only service'}); return
                if query:raise ValueError('Unexpected query parameters')
                lengths = self.headers.get_all('Content-Length', [])
                if self.headers.get('Transfer-Encoding'):raise ValueError('Transfer-Encoding is unsupported')
                if not lengths:
                    self.reply(411, {'error': 'Content-Length required'}); return
                if len(lengths) != 1:raise ValueError('Ambiguous Content-Length')
                length = number(lengths[0])
                if length > 1024*1024:
                    self.reply(413, {'error': 'Entry exceeds 1 MiB'}); return
                deadline = time.monotonic()+self.timeout
                data = bytearray()
                try:
                    while len(data) < length:
                        remaining = deadline-time.monotonic()
                        if remaining <= 0:raise TimeoutError
                        self.connection.settimeout(remaining)
                        chunk = self.rfile.read1(length-len(data))
                        if not chunk:break
                        data.extend(chunk)
                except TimeoutError:
                    self.close_connection = True
                    self.reply(408, {'error': 'Request body timed out'}); return
                except OSError:
                    self.close_connection = True
                    self.reply(400, {'error': 'Incomplete request body'}); return
                finally:
                    self.connection.settimeout(self.timeout)
                if len(data) != length:raise ValueError('Truncated body')
                action = lambda: self.server.log.append(bytes(data))
                kind = 'append'
            elif path == '/checkpoint':
                if query:raise ValueError('Unexpected query parameters')
                action = self.server.log.state; kind = 'json'
            elif path == '/snapshot':
                if query:raise ValueError('Unexpected query parameters')
                if self.server.snapshot is None:
                    self.reply(404, {'error': 'Snapshot not configured'}); return
                def read_snapshot():
                    path = self.server.snapshot
                    flags = os.O_RDONLY
                    if hasattr(os, 'O_NOFOLLOW'):
                        flags |= os.O_NOFOLLOW
                    fd = os.open(path, flags)
                    try:
                        info = os.fstat(fd)
                        if not stat.S_ISREG(info.st_mode):
                            raise OSError('Snapshot unavailable')
                        with os.fdopen(fd, 'rb') as source:
                            fd = -1
                            return source.read()
                    finally:
                        if fd >= 0:
                            os.close(fd)
                action = read_snapshot; kind = 'snapshot'
            elif path == '/proof/subtree':
                if set(query) != {'start', 'end', 'size'}:
                    raise ValueError('Expected start, end and size')
                if any(len(query[name]) != 1 for name in ('start', 'end', 'size')):
                    raise ValueError('Repeated query parameter')
                start = number(query['start'][0])
                end = number(query['end'][0])
                size = number(query['size'][0])
                action = lambda: self.server.log.subtree_proof(start, end, size)
                kind = 'json'
            elif path.startswith('/entries/'):
                if query:raise ValueError('Unexpected query parameters')
                index = number(path[len('/entries/'):])
                action = lambda: self.server.log.get_entry(index); kind = 'binary'
            elif path.startswith('/proof/inclusion/'):
                index = number(path[len('/proof/inclusion/'):])
                if set(query) != {'size'} or len(query['size']) != 1:raise ValueError('Expected size=N')
                size = number(query['size'][0])
                action = lambda: self.server.log.inclusion_proof(index, size); kind = 'json'
            elif path == '/proof/consistency':
                if set(query) != {'old', 'new'} or any(len(v) != 1 for v in query.values()):
                    raise ValueError('Expected old=N&new=M')
                old, new = number(query['old'][0]), number(query['new'][0])
                action = lambda: self.server.log.consistency_proof(old, new); kind = 'json'
            else:
                self.reply(404, {'error': 'Unknown endpoint'}); return
        except ValueError as error:
            self.reply(400, {'error': str(error)}); return
        try:
            value = action()
        except IndexError as error:
            self.reply(400, {'error': str(error)}); return
        except (ValueError, OSError):
            if kind == 'snapshot':
                self.reply(500, {'error': 'Snapshot unavailable'}); return
            self.reply(500, {'error': 'Persistent log unavailable or inconsistent'}); return
        if kind == 'append':value = dict(value, index=value['tree_size']-1)
        if kind not in ('binary', 'snapshot'):value = dict(value, unsigned=True)
        self.reply(201 if kind == 'append' else 200, value, kind in ('binary', 'snapshot'))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--data', default='/data')
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=8080)
    parser.add_argument('--snapshot')
    parser.add_argument('--ready-file')
    parser.add_argument(
        '--read-only',
        action='store_true',
        help='disable network append operations',
    )
    args = parser.parse_args()
    with LogServer(
            (args.host, args.port),
            args.data,
            args.snapshot,
            read_only=args.read_only) as server:
        if args.ready_file:
            ready = Path(args.ready_file)
            if ready.exists() or ready.is_symlink():
                raise ValueError('Ready file already exists')
            port = server.server_address[1]
            ready.write_text(json.dumps({'host': args.host, 'port': port}) + '\n')
        try:server.serve_forever()
        except KeyboardInterrupt:pass


if __name__ == '__main__':main()

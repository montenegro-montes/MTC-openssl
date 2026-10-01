"""Focused HTTP tests; loopback sockets and temporary storage only."""
import http.client
from contextlib import closing
import json
import socket
from pathlib import Path
import tempfile
import threading
import unittest

from core import root, evaluate, verify_consistency, verify_subtree_consistency
from log_service import LogServer


class ServiceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='mtc-http-test-')
        self.published_temp = tempfile.TemporaryDirectory(prefix='mtc-http-published-')
        self.directory = Path(self.temp.name)
        self.published = Path(self.published_temp.name)
        self.start()

    def start(self, snapshot=None):
        self.server = LogServer(('127.0.0.1', 0), self.directory, snapshot)
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={'poll_interval': 0.01})
        self.thread.start()

    def stop(self):
        self.server.shutdown(); self.thread.join(); self.server.server_close()

    def tearDown(self):
        self.stop()
        self.temp.cleanup()
        self.published_temp.cleanup()

    def request(self, method, path, body=None, headers=None):
        with closing(http.client.HTTPConnection(*self.server.server_address, timeout=5)) as connection:
            connection.request(method, path, body=body, headers=headers or {})
            response = connection.getresponse(); data = response.read()
            if response.getheader('Content-Type') == 'application/json':data = json.loads(data)
            return response.status, data

    def raw_request(self, request, disconnect=False):
        with socket.create_connection(self.server.server_address, timeout=5) as connection:
            connection.sendall(request)
            if disconnect:connection.shutdown(socket.SHUT_WR)
            with http.client.HTTPResponse(connection) as response:
                response.begin()
                return response.status, response.getheader('Allow'), json.loads(response.read())

    def test_body_timeout_and_truncation(self):
        request = b'POST /entries HTTP/1.0\r\nContent-Length: 8\r\n\r\nx'
        for disconnect, expected in [(False, 408), (True, 400)]:
            status, _, body = self.raw_request(request, disconnect)
            self.assertEqual(status, expected)
            self.assertIn('error', body)
            self.assertEqual(self.request('GET', '/checkpoint')[1]['tree_size'], 0)
        self.assertEqual(self.request('POST', '/entries', b'complete')[0], 201)

    def test_framing(self):
        for headers, expected in [(b'', 411),
                                  (b'Content-Length: 0\r\nContent-Length: 0\r\n', 400),
                                  (b'Content-Length: 0\r\nContent-Length: 1\r\n', 400),
                                  (b'Content-Length: invalid\r\n', 400)]:
            status, _, _ = self.raw_request(b'POST /entries HTTP/1.0\r\n'+headers+b'\r\n')
            self.assertEqual(status, expected)
        self.assertEqual(self.request('GET', '/checkpoint')[1]['tree_size'], 0)

    def test_method_allow(self):
        for method, path, allow in [('PUT', '/entries', 'POST'), ('GET', '/entries', 'POST'),
                                    ('POST', '/checkpoint', 'GET'), ('DELETE', '/entries/0', 'GET'),
                                    ('PUT', '/proof/inclusion/0?size=1', 'GET'),
                                    ('POST', '/proof/consistency?old=0&new=0', 'GET'),
                                    ('POST', '/proof/subtree?start=0&end=0&size=0', 'GET'),
                                    ('POST', '/snapshot', 'GET')]:
            status, header, body = self.raw_request(f'{method} {path} HTTP/1.0\r\n\r\n'.encode())
            self.assertEqual((status, header, body), (405, allow, {'error': 'Method not allowed'}))

    def test_explicit_boundaries(self):
        status, result = self.request('GET', '/proof/consistency?old=0&new=0')
        self.assertEqual(status, 200)
        self.assertEqual(result['proof'], [])
        self.assertEqual(result['old_hash'], root([]).hex())
        self.assertEqual(result['new_hash'], root([]).hex())
        self.assertEqual(self.request('GET', '/proof/consistency?old=-1&new=0')[0], 400)
        for _ in range(3):self.request('POST', '/entries', b'x')
        self.assertEqual(self.request('GET', '/proof/inclusion/2?size=2')[0], 400)

    def test_evolution_and_proofs(self):
        entries = [bytes([i, 0, 255])+b'\r\n' for i in range(16)]
        self.assertEqual(self.request('GET', '/checkpoint'),
                         (200, {'tree_size': 0, 'hash': root([]).hex(), 'unsigned': True}))
        for i, entry in enumerate(entries):
            status, state = self.request('POST', '/entries', entry)
            self.assertEqual(status, 201)
            self.assertEqual(state, {'index': i, 'tree_size': i+1,
                                    'hash': root(entries[:i+1]).hex(), 'unsigned': True})
            self.assertEqual(self.request('GET', f'/entries/{i}'), (200, entry))
        checkpoint = self.request('GET', '/checkpoint')
        self.assertEqual(checkpoint[1]['hash'], root(entries).hex())
        for size in (8, 16):
            status, result = self.request('GET', f'/proof/inclusion/3?size={size}')
            self.assertEqual(status, 200)
            self.assertTrue(result['unsigned'])
            self.assertEqual(evaluate(entries[3], 3, 0, size,
                                      [bytes.fromhex(p) for p in result['proof']]),
                             bytes.fromhex(result['hash']))
            self.assertEqual(result['hash'], root(entries[:size]).hex())
        for old, new in [(8,16), (3,8), (8,8), (0,16)]:
            status, result = self.request('GET', f'/proof/consistency?old={old}&new={new}')
            self.assertEqual(status, 200)
            self.assertEqual(result['old_hash'], root(entries[:old]).hex())
            self.assertEqual(result['new_hash'], root(entries[:new]).hex())
            self.assertTrue(verify_consistency(old, new, bytes.fromhex(result['old_hash']),
                                              bytes.fromhex(result['new_hash']),
                                              [bytes.fromhex(p) for p in result['proof']]))

        for start, end, size in [(0,4,8), (8,12,16)]:
            status, result = self.request(
                'GET', f'/proof/subtree?start={start}&end={end}&size={size}')
            self.assertEqual(status, 200)
            self.assertEqual(result['start'], start)
            self.assertEqual(result['end'], end)
            self.assertEqual(result['tree_size'], size)
            self.assertEqual(result['hash'], root(entries[start:end]).hex())
            self.assertTrue(result['unsigned'])
            self.assertTrue(verify_subtree_consistency(
                start, end, size,
                bytes.fromhex(result['hash']),
                root(entries[:size]),
                [bytes.fromhex(p) for p in result['proof']]))

        self.stop(); self.start()
        self.assertEqual(self.request('GET', '/checkpoint'), checkpoint)
        self.assertEqual(self.request('GET', '/entries/15'), (200, entries[15]))

    def test_invalid_requests(self):
        for path in ['/entries/-1', '/entries/no', '/entries/0',
                     '/proof/inclusion/0?size=0', '/proof/inclusion/0?size=17',
                     '/proof/inclusion/0?size=1&size=2',
                     '/proof/consistency?old=8', '/proof/consistency?old=no&new=16',
                     '/proof/consistency?old=2&new=1', '/proof/consistency?old=0&new=1',
                     '/proof/consistency?old=0&old=0&new=0',
                     '/proof/subtree?start=0&end=4',
                     '/proof/subtree?start=no&end=4&size=8',
                     '/proof/subtree?start=0&end=9&size=8',
                     '/proof/subtree?start=1&end=4&size=8',
                     '/proof/subtree?start=0&start=0&end=4&size=8',
                     '/checkpoint?unexpected=1',
                     '/snapshot?unexpected=1']:
            status, body = self.request('GET', path)
            self.assertEqual(status, 400, path)
            self.assertIn('error', body)
        self.assertEqual(self.request('PUT', '/entries', b'x')[0], 405)
        self.assertEqual(self.request('GET', '/missing')[0], 404)
        self.assertEqual(self.request('POST', '/entries', b'', {'Content-Length': 'bad'})[0], 400)
        self.assertEqual(self.request('POST', '/entries', b'', {'Content-Length': '1048577'})[0], 413)
        self.assertEqual(self.request('POST', '/entries', b'')[0], 201)
        self.assertEqual(self.request('GET', '/entries/0'), (200, b''))

    def test_snapshot_publication(self):
        self.assertEqual(self.request('GET', '/snapshot'),
                         (404, {'error': 'Snapshot not configured'}))

        self.stop()
        snapshot = self.published/'snapshot.mcf1'
        snapshot.write_bytes(b'MCF1\x00published')
        self.start(snapshot)

        self.assertEqual(self.request('GET', '/snapshot'),
                         (200, b'MCF1\x00published'))

        replacement = snapshot.with_suffix('.tmp')
        replacement.write_bytes(b'MCF1\x00replacement')
        replacement.replace(snapshot)

        self.assertEqual(self.request('GET', '/snapshot'),
                         (200, b'MCF1\x00replacement'))

        snapshot.unlink()
        self.assertEqual(self.request('GET', '/snapshot'),
                         (500, {'error': 'Snapshot unavailable'}))

    def test_snapshot_configuration_rejects_symlink(self):
        target = self.published/'snapshot-target.mcf1'
        link = self.published/'snapshot-link.mcf1'
        target.write_bytes(b'MCF1')
        link.symlink_to(target)
        with self.assertRaises(ValueError):
            LogServer(('127.0.0.1', 0), self.directory, link)

    def test_tampered_storage(self):
        self.request('POST', '/entries', b'original')
        (self.directory/'log/000000.entry').write_bytes(b'tampered')
        for method, path in [('GET','/checkpoint'), ('GET','/entries/0'),
                             ('GET','/proof/inclusion/0?size=1'),
                             ('GET','/proof/consistency?old=0&new=1'), ('POST','/entries')]:
            status, body = self.request(method, path, b'next' if method == 'POST' else None)
            self.assertEqual(status, 500)
            self.assertEqual(body, {'error': 'Persistent log unavailable or inconsistent'})
        self.assertFalse((self.directory/'log/000001.entry').exists())
        with self.assertRaises(ValueError):LogServer(('127.0.0.1', 0), self.directory)


if __name__ == '__main__':unittest.main()

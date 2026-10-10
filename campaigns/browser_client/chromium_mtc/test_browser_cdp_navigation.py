#!/usr/bin/env python3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

try:
    import browser_validation as bv
except ModuleNotFoundError:
    from . import browser_validation as bv


class FakeCdp:
    def __init__(self, fail_navigation=False):
        self.calls = []
        self.fail_navigation = fail_navigation
        self.closed = False

    def command(self, method, params=None):
        self.calls.append((method, params))
        if method == 'Page.navigate':
            if self.fail_navigation:
                raise ValueError('navigation rejected')
            return {'frameId': 'frame', 'loaderId': 'experimental-loader'}
        if method == 'Performance.getMetrics':
            return {'metrics': [{'name': 'Timestamp', 'value': 100.0}]}
        if method == 'Runtime.evaluate':
            return {'result': {'value': '{"url":"https://server.mtc.example.com:4433/test",'
                                        '"html":"<html><h1>MTC browser test</h1>'
                                        '<p id=\\"result\\">TLS browser validation page</p></html>"}'}}
        return {}

    def discard_events(self, *methods):
        self.calls.append(('discard', methods))

    def wait_navigation_load(self, frame_id, loader_id, navigation_timestamp, deadline):
        self.calls.append(('wait-navigation', (frame_id, loader_id, navigation_timestamp)))
        return {'load_event': {'method': 'Page.loadEventFired'},
                'lifecycle_event': {'method': 'Page.lifecycleEvent'}}

    def close(self):
        self.closed = True


class BrowserCdpNavigationTests(unittest.TestCase):
    @staticmethod
    def queued_connection(events=(), incoming=()):
        connection = bv.CdpConnection.__new__(bv.CdpConnection)
        connection.events = list(events)
        connection.socket = Mock()
        connection._receive = Mock(side_effect=list(incoming))
        return connection

    def test_command_starts_headless_browser_on_neutral_page(self):
        command = bv.browser_command('/chromium', Path('/profile'), Path('/case'), None,
                                     'https://server.mtc.example.com:4433/test')
        self.assertIn('--remote-debugging-port=0', command)
        self.assertIn('--remote-debugging-address=127.0.0.1', command)
        self.assertNotIn('--dump-dom', command)
        self.assertEqual(command[-1], 'about:blank')

    def test_stabilization_precedes_experimental_navigation_and_preserves_target(self):
        child = Mock(pid=123); child.wait.return_value = 0
        cdp = FakeCdp(); order = []
        with tempfile.TemporaryDirectory() as tmp, patch.object(bv, 'check_hostname'), \
                patch.object(bv.subprocess, 'Popen', return_value=child), \
                patch.object(bv, 'cdp_page', return_value=cdp), \
                patch.object(bv, 'stabilize_cdp', side_effect=lambda *_: order.append('stable') or [{'state':'complete'}]):
            output = Path(tmp); profile = output/'profile'; profile.mkdir()
            target = 'https://server.mtc.example.com:4433/test'
            result = bv.run_browser(['/chromium', 'about:blank'], output, 5,
                                    profile=profile, target_url=target,
                                    before_navigation=lambda: order.append('experiment'))
            self.assertEqual(result, 0)
            self.assertEqual(order, ['stable', 'experiment'])
            self.assertEqual(next(params['url'] for method, params in cdp.calls
                                  if method == 'Page.navigate'), target)
            self.assertEqual(bv.read(output/'cdp-navigation.json')['target_url'], target)
            self.assertEqual(bv.read(output/'cdp-navigation.json')['loader_id'], 'experimental-loader')
            self.assertEqual(bv.read(output/'browser-stabilization.json')['status'], 'PASS')
            self.assertIn('stabilization_ms', bv.read(output/'browser-timing.json'))
            self.assertTrue(cdp.closed)

    def test_cdp_failure_is_fail_closed_and_recorded(self):
        child = Mock(pid=123); child.wait.return_value = 0; child.poll.return_value = None
        cdp = FakeCdp(fail_navigation=True)
        with tempfile.TemporaryDirectory() as tmp, patch.object(bv, 'check_hostname'), \
                patch.object(bv.subprocess, 'Popen', return_value=child), \
                patch.object(bv, 'cdp_page', return_value=cdp), \
                patch.object(bv, 'stabilize_cdp', return_value=[{'state':'complete'}]), \
                patch.object(bv.os, 'killpg'):
            output = Path(tmp); profile = output/'profile'; profile.mkdir()
            with self.assertRaisesRegex(ValueError, 'navigation rejected'):
                bv.run_browser(['/chromium', 'about:blank'], output, 5, profile=profile,
                               target_url='https://server.mtc.example.com:4433/test',
                               before_navigation=Mock())
            self.assertEqual(bv.read(output/'cdp-navigation.json')['status'], 'FAIL')
            self.assertTrue(cdp.closed)

    def test_unstable_neutral_page_is_rejected(self):
        cdp = Mock()
        cdp.command.side_effect = [{}, {}, {}, {},
                                   {'result': {'value': '{"url":"about:blank","state":"loading"}'}}]
        with self.assertRaisesRegex(ValueError, 'not completely loaded'):
            bv.stabilize_cdp(cdp, bv.time.monotonic()+1, settle_seconds=0)

    def test_devtools_timeout_is_explicit(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(
                bv.time, 'monotonic', side_effect=[0, 2]):
            with self.assertRaisesRegex(ValueError, 'DevTools endpoint did not become ready'):
                bv.cdp_page(Path(tmp), 1)

    def test_browser_process_evidence_failure_still_terminates_child(self):
        child = Mock(pid=123); child.poll.return_value = None; child.wait.return_value = 0
        real_write = bv.write
        def failing_write(path, value):
            if Path(path).name == 'browser-process.json':
                raise OSError('evidence disk failure')
            return real_write(path, value)
        with tempfile.TemporaryDirectory() as tmp, patch.object(bv, 'check_hostname'), \
                patch.object(bv.subprocess, 'Popen', return_value=child), \
                patch.object(bv, 'write', side_effect=failing_write), \
                patch.object(bv.os, 'killpg') as killpg:
            with self.assertRaisesRegex(OSError, 'evidence disk failure'):
                bv.run_browser(['/chromium'], Path(tmp), 5)
        killpg.assert_called_with(123, bv.signal.SIGTERM)

    def test_failure_evidence_write_does_not_hide_original_or_skip_cleanup(self):
        child = Mock(pid=123); child.poll.return_value = None; child.wait.return_value = 0
        cdp = FakeCdp(fail_navigation=True); real_write = bv.write
        def failing_write(path, value):
            if Path(path).name == 'cdp-navigation.json':
                raise OSError('cannot record failure')
            return real_write(path, value)
        with tempfile.TemporaryDirectory() as tmp, patch.object(bv, 'check_hostname'), \
                patch.object(bv.subprocess, 'Popen', return_value=child), \
                patch.object(bv, 'cdp_page', return_value=cdp), \
                patch.object(bv, 'stabilize_cdp', return_value=[{'state':'complete'}]), \
                patch.object(bv, 'write', side_effect=failing_write), \
                patch.object(bv.os, 'killpg') as killpg:
            output = Path(tmp); profile = output/'profile'; profile.mkdir()
            with self.assertRaisesRegex(ValueError, 'navigation rejected'):
                bv.run_browser(['/chromium', 'about:blank'], output, 5, profile=profile,
                               target_url='https://server.mtc.example.com:4433/test',
                               before_navigation=Mock())
        killpg.assert_called_with(123, bv.signal.SIGTERM)

    def test_cdp_timeout_still_terminates_child(self):
        child = Mock(pid=123); child.poll.return_value = None; child.wait.return_value = 0
        with tempfile.TemporaryDirectory() as tmp, patch.object(bv, 'check_hostname'), \
                patch.object(bv.subprocess, 'Popen', return_value=child), \
                patch.object(bv, 'cdp_page', side_effect=TimeoutError('CDP timeout')), \
                patch.object(bv.os, 'killpg') as killpg:
            output = Path(tmp); profile = output/'profile'; profile.mkdir()
            with self.assertRaisesRegex(TimeoutError, 'CDP timeout'):
                bv.run_browser(['/chromium', 'about:blank'], output, 5, profile=profile,
                               target_url='https://server.mtc.example.com:4433/test',
                               before_navigation=Mock())
        killpg.assert_called_with(123, bv.signal.SIGTERM)

    def test_cleanup_failure_does_not_hide_navigation_error(self):
        child = Mock(pid=123); child.poll.return_value = None
        child.wait.side_effect = RuntimeError('wait cleanup failed')
        child.terminate.side_effect = RuntimeError('terminate cleanup failed')
        cdp = FakeCdp(fail_navigation=True)
        with tempfile.TemporaryDirectory() as tmp, patch.object(bv, 'check_hostname'), \
                patch.object(bv.subprocess, 'Popen', return_value=child), \
                patch.object(bv, 'cdp_page', return_value=cdp), \
                patch.object(bv, 'stabilize_cdp', return_value=[{'state':'complete'}]), \
                patch.object(bv.os, 'killpg', side_effect=PermissionError('signal cleanup failed')):
            output = Path(tmp); profile = output/'profile'; profile.mkdir()
            with self.assertRaisesRegex(ValueError, '^navigation rejected$'):
                bv.run_browser(['/chromium', 'about:blank'], output, 5, profile=profile,
                               target_url='https://server.mtc.example.com:4433/test',
                               before_navigation=Mock())

    def test_stale_about_blank_load_event_is_not_accepted(self):
        connection = self.queued_connection(events=[
            {'method': 'Page.loadEventFired', 'params': {'timestamp': 9.0}},
            {'method': 'Page.lifecycleEvent', 'params': {
                'name': 'load', 'frameId': 'frame', 'loaderId': 'about-loader'}},
            {'method': 'Page.loadEventFired', 'params': {'timestamp': 11.0}},
            {'method': 'Page.lifecycleEvent', 'params': {
                'name': 'load', 'frameId': 'frame', 'loaderId': 'experimental-loader'}},
        ])
        result = connection.wait_navigation_load('frame', 'experimental-loader', 10.0,
                                                 bv.time.monotonic()+1)
        self.assertEqual(result['load_event']['params']['timestamp'], 11.0)
        self.assertEqual(result['lifecycle_event']['params']['loaderId'], 'experimental-loader')

    def test_unrelated_queued_event_does_not_block_socket_navigation_events(self):
        unrelated = {'method': 'Page.frameStartedLoading', 'params': {'frameId': 'frame'}}
        load = {'method': 'Page.loadEventFired', 'params': {'timestamp': 11.0}}
        lifecycle = {'method': 'Page.lifecycleEvent', 'params': {
            'name': 'load', 'frameId': 'frame', 'loaderId': 'experimental-loader'}}
        connection = self.queued_connection([unrelated], [load, lifecycle])
        result = connection.wait_navigation_load(
            'frame', 'experimental-loader', 10.0, bv.time.monotonic()+1)
        self.assertIs(result['load_event'], load)
        self.assertIs(result['lifecycle_event'], lifecycle)
        self.assertEqual(connection.events, [unrelated])
        self.assertEqual(connection._receive.call_count, 2)

    def test_multiple_unrelated_events_remain_ordered_without_blocking_socket(self):
        queued = [
            {'method': 'Network.requestWillBeSent', 'params': {'requestId': '1'}},
            {'method': 'Page.frameStartedLoading', 'params': {'frameId': 'frame'}},
        ]
        incoming_unrelated = {'method': 'Network.responseReceived', 'params': {'requestId': '1'}}
        load = {'method': 'Page.loadEventFired', 'params': {'timestamp': 11.0}}
        lifecycle = {'method': 'Page.lifecycleEvent', 'params': {
            'name': 'load', 'frameId': 'frame', 'loaderId': 'experimental-loader'}}
        connection = self.queued_connection(queued, [incoming_unrelated, load, lifecycle])
        connection.wait_navigation_load(
            'frame', 'experimental-loader', 10.0, bv.time.monotonic()+1)
        self.assertEqual(connection.events, queued + [incoming_unrelated])
        self.assertEqual(connection._receive.call_count, 3)

    def test_timeout_restores_deferred_events(self):
        unrelated = {'method': 'Network.requestWillBeSent', 'params': {'requestId': '1'}}
        connection = self.queued_connection([unrelated])
        with patch.object(bv.time, 'monotonic', return_value=2.0):
            with self.assertRaisesRegex(ValueError, 'Timed out waiting for correlated'):
                connection.wait_navigation_load('frame', 'loader', 1.0, 1.0)
        self.assertEqual(connection.events, [unrelated])
        connection._receive.assert_not_called()

    def test_socket_exception_restores_deferred_events(self):
        unrelated = {'method': 'Network.requestWillBeSent', 'params': {'requestId': '1'}}
        connection = self.queued_connection([unrelated])
        connection._receive.side_effect = RuntimeError('socket read failed')
        with self.assertRaisesRegex(RuntimeError, 'socket read failed'):
            connection.wait_navigation_load(
                'frame', 'loader', 10.0, bv.time.monotonic()+1)
        self.assertEqual(connection.events, [unrelated])

    def test_strict_navigation_identifiers_are_required(self):
        wrong_load = {'method': 'Page.loadEventFired', 'params': {'timestamp': 9.0}}
        right_load = {'method': 'Page.loadEventFired', 'params': {'timestamp': 11.0}}
        wrong_lifecycle = {'method': 'Page.lifecycleEvent', 'params': {
            'name': 'load', 'frameId': 'frame', 'loaderId': 'about-loader'}}
        right_lifecycle = {'method': 'Page.lifecycleEvent', 'params': {
            'name': 'load', 'frameId': 'frame', 'loaderId': 'experimental-loader'}}
        connection = self.queued_connection(
            [wrong_load, wrong_lifecycle], [right_load, right_lifecycle])
        result = connection.wait_navigation_load(
            'frame', 'experimental-loader', 10.0, bv.time.monotonic()+1)
        self.assertIs(result['load_event'], right_load)
        self.assertIs(result['lifecycle_event'], right_lifecycle)
        self.assertEqual(connection.events, [wrong_load, wrong_lifecycle])

    def test_external_cdp_endpoint_is_rejected_before_connecting(self):
        with patch.object(bv.socket, 'create_connection') as connect:
            with self.assertRaisesRegex(ValueError, 'Unsafe DevTools WebSocket endpoint'):
                bv.CdpConnection('ws://192.0.2.10:9222/devtools/page/1', 1)
        connect.assert_not_called()


if __name__ == '__main__':
    unittest.main()

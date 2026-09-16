"""Offline regressions for the three-condition Native/PCAP validation gate; no TLS or Docker."""
import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('validation_run',Path(__file__).with_name('run.py'))
run=importlib.util.module_from_spec(spec);spec.loader.exec_module(run)


def probe(rtt):
    return 'QDISC_CLIENT_BEGIN\nqdisc netem 1: root delay 50ms\nQDISC_CLIENT_END\n' + '\n'.join(f'time={rtt} ms' for _ in range(20))


class PreflightTests(unittest.TestCase):
    def test_server_latency_uses_half_rtt(self):
        with patch.object(run.subprocess,'run') as call:
            run.apply_server_network('server-id','latency-100')
        self.assertEqual(call.call_args.args[0],['docker','exec','server-id','tc','qdisc','add','dev','eth0','root','netem','delay','50ms'])

    def test_server_local_unimpaired(self):
        with patch.object(run.subprocess,'run') as call:
            run.apply_server_network('server-id','local')
        call.assert_not_called()

    def test_constrained_uses_historical_helper(self):
        with patch.object(run.subprocess,'run') as call:
            run.apply_server_network('server-id','constrained')
        self.assertEqual(call.call_args_list[0].args[0][-2:],['python3','/opt/network-combined/apply_network.py'])
        self.assertIn('iperf3',call.call_args_list[1].args[0])
        self.assertIn('compose.network-combined.yaml',run.compose_for('constrained')[3])

    def test_latency_missing_server_delay_rejected(self):
        with self.assertRaisesRegex(RuntimeError,'both endpoints'):
            run.validate_network('latency-100','qdisc noqueue',probe(100),2000)
        self.assertEqual(run.validate_network('latency-100','qdisc netem delay 50ms',probe(100),2000)[2],15)

    def test_probe_timing_and_rtt_gates(self):
        with self.assertRaisesRegex(ValueError,'wall time'):
            run.validate_network('latency-100','qdisc netem delay 50ms',probe(100),50)
        with self.assertRaisesRegex(RuntimeError,'tolerance'):
            run.validate_network('latency-100','qdisc netem delay 50ms',probe(50),2000)

    def test_constrained_requires_rate_and_loss(self):
        q='qdisc tbf 1: root rate 5Mbit\nqdisc netem 10: parent 1:1 delay 50ms loss 1%'
        text='QDISC_CLIENT_BEGIN\n'+q+'\nQDISC_CLIENT_END\n200 packets transmitted, 198 received, 1% packet loss\n'+ '\n'.join('time=100 ms' for _ in range(198))+'\n4.5 Mbits/sec'
        self.assertEqual(run.validate_network('constrained',q,text,7000)[0]['measured_bandwidth_mbit'],4.5)
        for bad in [q.replace('loss 1%',''),q.replace('rate 5Mbit','rate 1Mbit'),q.replace('parent 1:1','parent 2:1')]:
            with self.assertRaises(ValueError):run.validate_network('constrained',bad,text,7000)

    def test_dispatch_stops_on_failure(self):
        with tempfile.TemporaryDirectory(dir=run.REPO/'artifacts/results') as tmp:
            root=Path(tmp)
            def condition(root,name):
                if name=='latency-100':raise RuntimeError('probe failed')
                run.save(root/f'preflight-{name}-status.json',{'passed':True})
            with patch.object(run,'execute_condition_preflight',side_effect=condition) as call:
                with self.assertRaisesRegex(RuntimeError,'probe failed'):run.execute_preflight(root)
            self.assertEqual([c.args[1] for c in call.call_args_list],['local','latency-100'])
            self.assertFalse(run.load(root/'preflight-status.json')['passed'])

    def test_validation_client_can_find_shared_capture_module(self):
        override=Path(__file__).with_name("compose.validation.yaml").read_text()
        self.assertIn("PYTHONPATH: /opt/measurement",override)

    def test_full_stays_blocked(self):
        with patch.object(run.sys,'argv',['run.py','--full','--root',str(run.REPO/'artifacts/results/not-started-offline-test')]):
            with self.assertRaisesRegex(SystemExit,'requires --preflight-root'):run.main()

if __name__=='__main__':unittest.main()

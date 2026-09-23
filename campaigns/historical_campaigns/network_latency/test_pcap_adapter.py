"""Offline checks for latency PCAP opt-in wiring; no Docker or TLS traffic."""
import ast
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[3]


class LatencyPcapAdapterTests(unittest.TestCase):
    def test_cli_and_environment_are_opt_in(self):
        source = (Path(__file__).parent / 'run.py').read_text()
        self.assertIn("--pcap", source)
        self.assertIn("MEASUREMENT_PCAP", source)
        self.assertIn("'1' if args.pcap else '0'", source)

    def test_network_parameters_and_original_measurement_are_untouched(self):
        runner = (Path(__file__).parent / 'run.py').read_text()
        client = (Path(__file__).parent / 'client.sh').read_text()
        self.assertIn("tc','qdisc','add','dev','eth0','root','netem','delay'", runner)
        self.assertIn('NETWORK_HALF_DELAY_MS', client)
        self.assertIn("'handshake_wall_ms':m['handshake_wall_ms']", (ROOT / 'src/mtc/benchmark.py').read_text())
        self.assertIn("'transport_total_bytes':m['transport_read_bytes']+m['transport_written_bytes']", (ROOT / 'src/mtc/benchmark.py').read_text())

    def test_warmup_policy_and_cleanup_order_are_explicit(self):
        measure = (ROOT / 'campaigns/historical_campaigns/controlled_n16_campaign/measure.py').read_text()
        self.assertIn('with observation(out,scenario,round_number,order,warm', measure)
        self.assertIn('if warm or os.environ.get', (ROOT / 'campaigns/common/pcap_capture.py').read_text())
        runner = (Path(__file__).parent / 'run.py').read_text()
        self.assertIn('with capture_session(COMPOSE,directory,env,args.pcap',runner)
        self.assertLess(runner.index('with capture_session'),runner.index('server_after='))

    def test_all_edited_python_is_valid(self):
        for path in (Path(__file__).parent / 'run.py', Path(__file__).parent / 'test_pcap_adapter.py'):
            ast.parse(path.read_text(), filename=str(path))


if __name__ == '__main__':
    unittest.main()

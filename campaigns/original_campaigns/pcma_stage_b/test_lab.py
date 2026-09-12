"""Small deterministic design/parser/statistics tests. No Docker or sockets."""
import contextlib
import copy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from design import load_config,plan
from runner import parse_metrics
from analysis import bootstrap,compute
from cli import main

class LaboratoryTests(unittest.TestCase):
    def setUp(self):self.config=load_config(Path(__file__).parent/'configs/stage-b1.json')
    def test_counts_and_pairing(self):
        p=plan(self.config,'stage-b1')
        self.assertEqual((p['expected_campaigns'],p['measured_handshakes'],p['warmup_handshakes'],p['expected_handshakes']),(90,10800,1800,12600))
        self.assertTrue(all(len(c['arms'])==4 and len(c['sequence'])==35 for c in p['cells']))
        self.assertEqual(p,plan(self.config,'stage-b1'))
        d=plan(self.config,'diagnostic');self.assertEqual(d['expected_handshakes'],8);self.assertEqual(d['cells'][0]['sequence'],[0,1,2,8])
    def test_b2_selection_gate(self):
        c=load_config(Path(__file__).parent/'configs/stage-b2-selection.json')
        with self.assertRaises(ValueError):plan(c,'stage-b2')
        c.update(selection_approved=True,selection_justification='unit test only')
        p=plan(c,'stage-b2');self.assertEqual(p['expected_campaigns'],30)
        groups={}
        for cell in p['cells']:
            k=(cell['N'],cell['workload'],cell['repetition'])
            if k in groups:self.assertEqual(groups[k],cell['sequence'])
            groups[k]=cell['sequence']
    def test_no_arguments_and_plan_do_not_execute(self):
        with patch('runner.execute',side_effect=AssertionError('forbidden')):
            with contextlib.redirect_stdout(io.StringIO()) as out:main([])
            self.assertIn('--stage-b1',out.getvalue())
            with contextlib.redirect_stdout(io.StringIO()) as out:main(['--diagnostic','--plan'])
            self.assertEqual(json.loads(out.getvalue())['expected_handshakes'],8)
    def test_metrics_parser(self):
        self.assertEqual(parse_metrics('PCMA_METRICS {"success":true}\n'),{'success':True})
        for text in ('','PCMA_METRICS {}\nPCMA_METRICS {}\n'):
            with self.assertRaises(ValueError):parse_metrics(text)
    def test_campaign_level_statistics(self):
        self.assertEqual(bootstrap([1,1,1],20,17),(1,1))
        self.assertEqual(bootstrap([1],20,17),(None,None))
        c=copy.deepcopy(self.config);c['bootstrap_resamples']=20
        rows=[]
        for campaign in range(3):
            for t in range(2):
                for scenario in ('pq-compact-warm','pq-compact-pcma'):
                    r=dict(campaign_id=str(campaign),sequence_position=str(t),is_warmup='0',N='16',workload='uniform',network_profile='baseline',scenario=scenario,cache_budget='2048' if scenario.endswith('pcma') else '0',cache_policy='lru')
                    for metric in ('tls_total_bytes','handshake_total_bytes','server_authentication_bytes','wall_ms','cpu_ms','server_cpu_ms'):r[metric]=10 if scenario.endswith('warm') else 9
                    rows.append(r)
        _,_,effects,paired=compute(rows,c)
        self.assertEqual(len(effects),18)
        self.assertTrue(all(r['median_paired_difference']==-1 and r['ci95_low']==-1 and r['campaigns']==3 for r in paired))

if __name__=='__main__':unittest.main(verbosity=2)

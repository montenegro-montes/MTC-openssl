"""Offline regressions: no Docker, sockets, fixture issuance or TLS."""
import contextlib
import copy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from . import cli, fixtures
from .common import cases, protocol, schedule, tls_arguments, image_id, verify_inventory, sha
from .metrics import parse_metrics, validate
from .analyze import effect_summary, summarize, METRICS


def metric_pair(mutual=True):
    client = {'side': 'client', 'profile_valid': 1, 'client_random': 'a'*64, 'reused': 0,
              'server_certificate_message_bytes': 500, 'client_certificate_message_bytes': 500 if mutual else 0,
              'server_certificate_verify_message_bytes': 80, 'client_certificate_verify_message_bytes': 80 if mutual else 0,
              'certificate_message_bytes': 500, 'certificate_verify_message_bytes': 80,
              'handshake_read_bytes': 1000, 'handshake_written_bytes': 900,
              'transport_read_bytes': 1200, 'transport_written_bytes': 1100,
              'handshake_wall_ms': 2, 'handshake_cpu_ms': 1,
              'tcp_connect_wall_ms_native': .5, 'connection_establishment_wall_ms_native': 2.5}
    server = dict(client, side='server', handshake_read_bytes=900, handshake_written_bytes=1000)
    client_log = ('Verification: OK\nVerify return code: 0 (ok)\nNew, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384\n'
                  'Peer Temp Key: X25519\nMTC_VERIFY {"mtc_credential_auth_ms":0.2}\n')
    server_log = ('SSL_accept:SSLv3/TLS read finished\nSSL_accept:SSLv3/TLS read client certificate\n'
                  'SSL_accept:SSLv3/TLS read certificate verify\nMTC_VERIFY {"mtc_credential_auth_ms":0.3}\n')
    return client_log, server_log, client, server


class MatrixTests(unittest.TestCase):
    def test_counts_and_exclusions(self):
        spec = protocol(); cc = cases(spec)
        self.assertEqual(len(cc), 10)
        self.assertEqual(len({c['id'] for c in cc}), 10)
        self.assertEqual(sum(c['credential']=='x509-ca' for c in cc), 4)
        self.assertEqual({c['credential'] for c in cc}, {'x509-ca', 'mtc-landmark'})
        full = schedule(spec, 'full')
        self.assertEqual(len(full), 40)
        self.assertEqual(sum(len(r['cases']) for b in full for r in b['rounds'] if r['phase']=='measured'), 12000)
        self.assertEqual(sum(len(r['cases']) for b in full for r in b['rounds'] if r['phase']=='warmup'), 2000)

    def test_schedule_pairing_and_seed(self):
        spec = protocol(); a = schedule(spec, 'full')
        self.assertEqual(a, schedule(spec, 'full'))
        other = dict(spec, seed=spec['seed']+1)
        self.assertNotEqual(a, schedule(other, 'full'))
        expected = {c['id'] for c in cases(spec)}
        for block in a:
            for rnd in block['rounds']:
                self.assertEqual({c['id'] for c in rnd['cases']}, expected)

    def test_cli_plan_does_not_execute(self):
        with patch('sys.argv', ['cli', 'plan']), patch('subprocess.run', side_effect=AssertionError('execution')), \
             patch('subprocess.check_output', side_effect=AssertionError('execution')), contextlib.redirect_stdout(io.StringIO()) as out:
            cli.main()
        self.assertEqual(json.loads(out.getvalue())['measured_attempts'], 12000)

    def test_fixture_plan_does_not_execute_or_write(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            with patch.object(fixtures, 'REPO', root), patch('sys.argv', ['fixtures', '--image', 'sha256:'+'0'*64,
                 '--output', str(root/'artifacts/network-authentication/new')]), \
                 patch('subprocess.run', side_effect=AssertionError('execution')), contextlib.redirect_stdout(io.StringIO()):
                fixtures.main()
            self.assertFalse((root/'artifacts').exists())

    def test_mutual_vs_server_flags(self):
        for c in cases(protocol()):
            server, client = tls_arguments(c)
            mutual = c['authentication']=='mutual'
            self.assertEqual('-Verify' in server, mutual)
            self.assertEqual('-cert' in client, mutual)
            self.assertIn('-no_ticket', client); self.assertIn('-num_tickets', server)
            if mutual:
                _, negative = tls_arguments(c, missing_client=True)
                self.assertNotIn('-cert', negative)
                self.assertNotIn('-key', negative)
            self.assertIn('-naccept', server)

    def test_identical_server_fixture_across_auth_modes(self):
        for c in cases(protocol()):
            if c['authentication']!='mutual': continue
            a, _ = tls_arguments(c)
            b, _ = tls_arguments(dict(c, authentication='server-only'))
            for flag in ['-cert','-key']:
                self.assertEqual(a[a.index(flag)+1], b[b.index(flag)+1])

    def test_requires_immutable_image(self):
        with self.assertRaises(ValueError): image_id('image:latest')
        self.assertEqual(image_id('sha256:'+'f'*64), 'sha256:'+'f'*64)

    def test_inventory_detects_mutation(self):
        with tempfile.TemporaryDirectory() as temp:
            p = Path(temp)/'fixture'; p.write_text('before')
            inventory = {'fixture': sha(p)}
            verify_inventory(Path(temp), inventory)
            p.write_text('after')
            with self.assertRaises(ValueError): verify_inventory(Path(temp), inventory)


class ExecutionBoundaryTests(unittest.TestCase):
    def test_full_needs_preflight_before_any_docker(self):
        from .runner import execute
        with tempfile.TemporaryDirectory() as temp, patch('subprocess.run', side_effect=AssertionError('Docker')), \
             patch('subprocess.Popen', side_effect=AssertionError('Docker')):
            root=Path(temp)
            with self.assertRaises(FileNotFoundError):execute(root,'full',{})
            self.assertFalse((root/'full').exists())

    def test_gate_detects_modified_evidence(self):
        from .runner import gate,seal
        from .common import save
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp); (root/'manifest.json').write_text('{}')
            stage=root/'preflight';stage.mkdir()
            save(stage/'status.json',{'passed':True,'manifest_sha256':sha(root/'manifest.json')})
            evidence=stage/'raw.log';evidence.write_text('original')
            seal(stage);gate(root,'preflight')
            evidence.write_text('modified')
            with self.assertRaises(ValueError):gate(root,'preflight')

    def test_cleanup_only_owns_created_resources(self):
        from .runner import Lab
        with tempfile.TemporaryDirectory() as temp:
            lab=Lab({},Path(temp));lab.created=['mtnetauth-owned-server'];lab.network_created=False
            with patch.object(lab,'command') as command:
                command.return_value.returncode=0
                lab.close()
                command.assert_called_once_with(['docker','rm','-f','mtnetauth-owned-server'],check=False)

    def test_shaping_has_symmetric_loss_and_rate(self):
        from .runner import Lab
        with tempfile.TemporaryDirectory() as temp:
            lab=Lab({},Path(temp))
            with patch.object(lab,'exec') as command, patch.object(lab,'qdisc'):
                lab.shape({'rtt_ms':100,'rate_mbit':5,'loss_percent':1})
                calls=command.call_args_list
                self.assertEqual(len(calls),4)
                for role in ['client','server']:
                    args=[c.args[1] for c in calls if c.args[0]==role]
                    self.assertTrue(any('tbf' in a and '5mbit' in a for a in args))
                    self.assertTrue(any('netem' in a and '50ms' in a and '1%' in a for a in args))


class MetricsTests(unittest.TestCase):
    def case(self, mutual=True):
        return {'credential': 'mtc-landmark', 'authentication': 'mutual' if mutual else 'server-only'}

    def test_mutual_and_server_only(self):
        for mutual in [True, False]:
            cl, sl, c, s = metric_pair(mutual)
            r = validate(self.case(mutual), cl, sl, c, s)
            self.assertEqual(r['certificate_total_bytes'], 1000 if mutual else 500)
            self.assertEqual(r['client_mtc_verify_ms'], .2)
            self.assertEqual(r['server_mtc_verify_ms'], .3)

    def test_endpoint_mismatch_rejected(self):
        cl, sl, c, s = metric_pair(); s['client_certificate_message_bytes'] += 1
        with self.assertRaises(ValueError): validate(self.case(), cl, sl, c, s)

    def test_server_only_cannot_silently_be_mutual(self):
        with self.assertRaises(ValueError): validate(self.case(False), *metric_pair(True))

    def test_mutual_cannot_fall_back(self):
        with self.assertRaises(ValueError): validate(self.case(True), *metric_pair(False))

    def test_resume_invalid_profile_and_missing_finished(self):
        for field, value in [('reused', 1), ('profile_valid', 0), ('handshake_wall_ms', float('nan'))]:
            cl, sl, c, s = metric_pair(); c[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError): validate(self.case(), cl, sl, c, s)
        cl, sl, c, s = metric_pair()
        with self.assertRaises(ValueError): validate(self.case(), cl, '', c, s)

    def test_legacy_semantics(self):
        cl, sl, c, s = metric_pair(); c['certificate_message_bytes'] = 1000
        with self.assertRaises(ValueError): validate(self.case(), cl, sl, c, s)

    def test_duplicate_metric_records_rejected(self):
        text='PROFILE_METRICS '+json.dumps(metric_pair()[2])+'\n'
        self.assertEqual(parse_metrics(text)['client_random'], 'a'*64)
        with self.assertRaises(ValueError): parse_metrics(text+text)


class AnalysisTests(unittest.TestCase):
    def population(self):
        spec = dict(protocol(), profiles={'ecdsa-p256':[16]}, measured_rounds=1, bootstrap_resamples=100)
        rows=[]
        for rep in range(1,6):
            for c in cases(spec):
                value = {('server-only','x509-ca'):10, ('server-only','mtc-landmark'):8,
                         ('mutual','x509-ca'):20, ('mutual','mtc-landmark'):17}[(c['authentication'],c['credential'])]
                rows.append({'phase':'measured','campaign':f'local-c{rep}','condition':'local','repetition':rep,
                             'round':1,'case':c,'success':1,**{m:value for m in METRICS}})
        return rows,spec

    def test_paired_and_interaction(self):
        rows,spec=self.population(); report=summarize(rows,spec)
        self.assertTrue(all(r['median_campaign_effect']==-1 for r in report['mutual_minus_server_only_interaction']))
        self.assertTrue(all(r['pairs_unavailable']==0 for r in report['mtc_minus_x509']))

    def test_failure_not_imputed_and_ci_withheld(self):
        rows,spec=self.population(); rows[0]['success']=0
        for m in METRICS: rows[0].pop(m)
        report=summarize(rows,spec)
        self.assertTrue(any(c['failure_rate']==.2 for c in report['cells']))
        interaction=report['mutual_minus_server_only_interaction'][0]
        self.assertEqual(interaction['pairs_unavailable'],1)
        self.assertIsNone(interaction['bootstrap95'])

    def test_warmups_excluded(self):
        rows,spec=self.population(); rows += [dict(rows[0],phase='warmup',success=0)]
        self.assertEqual(sum(c['attempts'] for c in summarize(rows,spec)['cells']),20)

    def test_all_pairs_failed(self):
        rows,spec=self.population()
        for r in rows:r['success']=0
        report=summarize(rows,spec)
        self.assertTrue(all(c['failure_rate']==1 for c in report['cells']))
        self.assertTrue(all(r['median_campaign_effect'] is None for r in report['mtc_minus_x509']))

    def test_duplicate_observation_rejected(self):
        rows,spec=self.population()
        with self.assertRaises(ValueError):summarize(rows+[rows[0]],spec)


if __name__=='__main__':
    unittest.main()

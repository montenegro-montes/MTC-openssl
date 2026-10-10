"""Synthetic credentials are confined to TemporaryDirectory; no real browser/network."""
import copy
from datetime import datetime, timedelta, timezone
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes as alg, serialization as ser
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID as eku

REPO = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('browser_validation', REPO/'campaigns/browser_client/chromium_mtc/browser_validation.py')
bv = importlib.util.module_from_spec(spec); spec.loader.exec_module(bv)
from config_formats import (MCA2Authority, MCP2Checkpoint, MTB2Bundle,
                            encode_mtb2)


class Credentials(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='synthetic-mtc-test-')
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name).resolve()
        self.x = bv.generate_x509(self.repo)
        self.output = self.repo/'audit'; self.output.mkdir()

    def make_mtc(self):
        c = bv.core
        ca_id = '32473.200'
        fixture = self.repo/'artifacts/mtc'/('browser-'+bv.HOST.replace('.', '-')+'-20260925T000000Z')
        directory = fixture/'batch16/mtc/ecdsa-p256'; directory.mkdir(parents=True)
        population = fixture/'population/ecdsa-p256'; population.mkdir(parents=True)
        (population/'0.key').write_bytes((self.x/'server.key').read_bytes())
        original = c.from_pem((self.x/'server.pem').read_bytes())
        tbs = [c.mtc_tbs(original, ca_id, i) for i in range(16)]
        entries = [c.entry(t) for t in tbs]; root = c.root(entries)
        ids = [ca_id, '32473.201']; keys = [ec.generate_private_key(ec.SECP256R1()) for _ in ids]
        signers = [(name, key.public_key().public_bytes(ser.Encoding.DER, ser.PublicFormat.SubjectPublicKeyInfo)) for name, key in zip(ids,keys)]
        timestamp = int(datetime.now(timezone.utc).timestamp())-1
        signatures = [(name, key.sign(c.message(name,ca_id,0,16,root,timestamp),ec.ECDSA(alg.SHA256()))) for name,key in zip(ids,keys)]
        subs = c.cover(0,16)
        authority = MCA2Authority(ca_id, tuple(signers), 1,
                                  1 << 48, (1 << 48) + 15)
        checkpoint = MCP2Checkpoint(
            16, timestamp, root, tuple(signatures),
            tuple((a, b, c.root(entries[a:b])) for a, b in subs))
        trust = encode_mtb2(MTB2Bundle(authority, checkpoint, 1))
        (directory/'trust.bin').write_bytes(trust)
        proof = c.proof(0,8,c.inclusion(entries[:8],0),[])
        (directory/'landmark-0000.pem').write_bytes(c.pem(c.certificate(tbs[0],proof)))
        meta=dict(profile=bv.PROFILE,tree_size=16,draft=c.DRAFT,trust_anchor_draft=c.TA_DRAFT,merkle_hash='SHA-256',implementation_algorithm='EC',ca_id=ca_id)
        bv.write(directory/'manifest.json',meta);bv.write(directory/'fixture-sha256.json',bv.hashes(directory))
        bv.write(fixture/'manifest.json',dict(server_hostname=bv.HOST,profiles=[bv.PROFILE],sizes=[16],provenance=dict(image_id='sha256:'+'1'*64)))
        evidence=fixture.with_name(fixture.name+'-validation');evidence.mkdir()
        bv.write(evidence/'validation.json',dict(passed=True,server_hostname=bv.HOST,cells=[dict(profile=bv.PROFILE,tree_size=16,mtc_mode='landmark',success=True)],fixture_hashes=bv.hashes(fixture),provenance=dict(image_id='sha256:'+'1'*64)))
        return fixture

    def rewrite_leaf(self, *, san=bv.HOST, ca=False, server_auth=True, before=None, after=None):

        original=x509.load_pem_x509_certificate((self.x/'server.pem').read_bytes())
        key=ser.load_pem_private_key((self.x/'root.key').read_bytes(),None)
        now=datetime.now(timezone.utc)
        builder=x509.CertificateBuilder().subject_name(original.subject).issuer_name(original.issuer).public_key(original.public_key()).serial_number(original.serial_number).not_valid_before(before or now-timedelta(minutes=1)).not_valid_after(after or now+timedelta(days=1))
        builder=builder.add_extension(x509.BasicConstraints(ca=ca,path_length=None),True).add_extension(x509.SubjectAlternativeName([x509.DNSName(san)]),False).add_extension(x509.KeyUsage(True,False,False,False,False,False,False,False,False),True)
        if server_auth: builder=builder.add_extension(x509.ExtendedKeyUsage([eku.SERVER_AUTH]),False)
        (self.x/'server.pem').write_bytes(builder.sign(key,alg.SHA256()).public_bytes(ser.Encoding.PEM))
        (self.x/'manifest.json').unlink()

    def test_legacy_cryptography_dates(self):

        real_loader=x509.load_pem_x509_certificate
        class LegacyCertificate:
            def __init__(self, cert): self.cert=cert
            def __getattr__(self, name):
                if name.endswith('_utc'): raise AttributeError(name)
                if name in ('not_valid_before','not_valid_after'):
                    return getattr(self.cert,name+'_utc').replace(tzinfo=None)
                return getattr(self.cert,name)
        f=self.make_mtc()
        with patch.object(x509,'load_pem_x509_certificate',side_effect=lambda raw: LegacyCertificate(real_loader(raw))):
            self.assertTrue(bv.validate_mtc(f)['key_match'])
            self.assertTrue(bv.validate_x509(self.x)['root_self_signature_verified'])

    def test_validator_api_failure_never_generates(self):
        with patch.object(bv,'validate_mtc',side_effect=AttributeError('old API')), patch.object(bv,'generate_mtc') as generate:
            with self.assertRaisesRegex(ValueError,'generation disabled'):
                bv.select_or_generate([self.x],bv.validate_mtc,generate)
            generate.assert_not_called()

    def test_public_root_saved_with_audit(self):
        f=self.make_mtc()
        with patch.object(bv,'root_trust',return_value=dict(status='TRUSTED')):
            result=bv.prepare_credentials(self.repo,self.output,'mt-tls-mtc:local')
        root=Path(result['x509']['root']);saved=Path(result['x509']['root_certificate_copy'])
        self.assertEqual(root.read_bytes(),saved.read_bytes())
        self.assertEqual(bv.sha(saved),result['x509']['root_certificate_copy_sha256'])
        self.assertTrue(result['x509']['root_self_signature_verified'])
        self.assertIn('-check_ss_sig',result['x509']['root_verification_command'])
        self.assertFalse(list(self.output.glob('*.key')))

    def test_valid_mtc_selection(self):
        f=self.make_mtc();selected,audit=bv.discover([f],bv.validate_mtc)
        self.assertEqual(selected['fixture'],str(f));self.assertTrue(selected['complete_evidence']);self.assertTrue(audit[0]['selected'])

    def test_mtc_wrong_hostname(self):
        f=self.make_mtc();d=bv.read(f/'manifest.json');d['server_hostname']='server';(f/'manifest.json').write_text(json.dumps(d))
        self.assertIsNone(bv.discover([f],bv.validate_mtc)[0])

    def test_mtc_stale_hash(self):
        f=self.make_mtc();(f/'unexpected-file').write_text('synthetic corruption')
        with self.assertRaisesRegex(ValueError,'hash'): bv.validate_mtc(f)

    def test_mtc_failed_evidence(self):
        f=self.make_mtc();p=f.with_name(f.name+'-validation')/'validation.json';d=bv.read(p);d['passed']=False;p.write_text(json.dumps(d))
        with self.assertRaisesRegex(ValueError,'does not PASS'): bv.validate_mtc(f)

    def test_checkpoint_corruption_rejected(self):
        f=self.make_mtc();p=f/'batch16/mtc/ecdsa-p256/trust.bin';raw=bytearray(p.read_bytes());raw[-1]^=1;p.write_bytes(raw)
        self.assertIsNone(bv.discover([f],bv.validate_mtc)[0])

    def test_anchor_reused(self):
        f=self.make_mtc();m=bv.validate_mtc(f);p=f.with_name(f.name+'-chromium.json');bv.write(p,bv.expected_anchor(m))
        result=bv.choose_anchor(m,self.output);self.assertEqual(result['anchor_origin'],'reused');self.assertEqual(result['anchor'],str(p))

    def test_mismatched_anchor_preserved_regenerated(self):
        f=self.make_mtc();m=bv.validate_mtc(f);p=f.with_name(f.name+'-chromium.json');p.write_text('{}\n')
        result=bv.choose_anchor(m,self.output)
        self.assertEqual(result['anchor_origin'],'generated');self.assertEqual(p.read_text(),'{}\n');self.assertEqual(bv.read(result['anchor']),bv.expected_anchor(m))

    def test_valid_x509_selected(self):
        selected,_=bv.discover([self.x],bv.validate_x509)
        self.assertTrue(selected['hostname_validation']);self.assertTrue(selected['key_match'])

    def test_x509_wrong_san(self):
        self.rewrite_leaf(san='localhost')
        with self.assertRaisesRegex(ValueError,'SAN'): bv.validate_x509(self.x)

    def test_x509_ca_leaf(self):
        self.rewrite_leaf(ca=True)
        with self.assertRaisesRegex(ValueError,'CA leaf'): bv.validate_x509(self.x)

    def test_x509_missing_server_auth(self):
        self.rewrite_leaf(server_auth=False)
        self.assertIsNone(bv.discover([self.x],bv.validate_x509)[0])

    def test_x509_key_mismatch(self):
        (self.x/'server.key').write_bytes((self.x/'root.key').read_bytes())
        with self.assertRaisesRegex(ValueError,'mismatch'): bv.validate_x509(self.x)

    def test_x509_expired(self):
        now=datetime.now(timezone.utc);self.rewrite_leaf(before=now-timedelta(days=3),after=now-timedelta(days=1))
        with self.assertRaisesRegex(ValueError,'Expired'): bv.validate_x509(self.x)

    def test_x509_not_yet_valid(self):
        now=datetime.now(timezone.utc);self.rewrite_leaf(before=now+timedelta(days=1),after=now+timedelta(days=3))
        with self.assertRaisesRegex(ValueError,'not-yet-valid'): bv.validate_x509(self.x)

    def test_selection_deterministic_both_kinds(self):
        for kind in ('mtc','x509'):
            paths=[self.repo/(kind+'-20260101T000000Z'),self.repo/(kind+'-20260102T000000Z')]
            validator=lambda p: dict(fixture=str(p),complete_evidence=True)
            first=bv.discover(paths,validator)[0];second=bv.discover(reversed(paths),validator)[0]
            self.assertEqual(first,second);self.assertEqual(first['fixture'],str(paths[1]))

    def test_fallback_only_when_no_valid_both_kinds(self):
        for validator,path in ((bv.validate_mtc,self.make_mtc()),(bv.validate_x509,self.x)):
            with patch.object(bv,'generate_x509',return_value=path) as generator:
                selected,_=bv.select_or_generate([path],validator,generator);generator.assert_not_called();self.assertEqual(selected['origin'],'reused')
                selected,_=bv.select_or_generate([],validator,generator);generator.assert_called_once();self.assertEqual(selected['origin'],'generated')

    def test_mutations_preserve_original(self):
        m=bv.validate_mtc(self.make_mtc());a=bv.expected_anchor(m);original=json.dumps(a,sort_keys=True)
        changed=bv.mutate_anchor(a,'mtc-bad-merkle')
        changed['landmark']['trusted_subtrees'][0]['hash']=a['landmark']['trusted_subtrees'][0]['hash'];self.assertEqual(changed,a)
        changed=bv.mutate_anchor(a,'mtc-bad-serial')
        self.assertEqual(changed['max_serial']-changed['min_serial'],a['max_serial']-a['min_serial'])
        for key in ('min_serial','max_serial'):
            self.assertEqual(changed[key],a[key]+1);changed[key]=a[key];changed[key+'_hex']=a[key+'_hex']
        self.assertEqual(changed,a);self.assertEqual(json.dumps(a,sort_keys=True),original)


class Safety(unittest.TestCase):
    def test_no_bypass_flags(self):
        command=bv.browser_command('/browser',Path('/tmp/profile'),Path('/tmp/case'),None,'https://'+bv.HOST)
        for flag in ('--ignore-certificate-errors','--allow-insecure-localhost'):
            self.assertNotIn(flag,command)

    def test_plan_status_no_launch_or_generation(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(bv,'REPO',Path(tmp)), patch.object(bv,'command') as cmd, patch.object(bv.subprocess,'Popen') as launch, patch.object(bv,'prepare_credentials') as prepare:
            self.assertEqual(bv.main(['plan']),0);self.assertEqual(bv.main(['status']),0)
            cmd.assert_not_called();launch.assert_not_called();prepare.assert_not_called()

    def test_selected_tai_from_wire(self):
        import base64
        c=bv.core
        selected='32473.200.1.1.1'
        extension=c.uint(0xca34,2)+c.vec(c.vec(c.vec(c.relid(selected),1)))
        body=c.vec(extension);wire=b'\x08'+c.uint(len(body),3)+body
        events=[('SSL_HANDSHAKE_MESSAGE_RECEIVED',dict(type=8,bytes=base64.b64encode(wire).decode()),0,1)]
        self.assertTrue(bv.encrypted_extensions_selected(events,selected))
        events[0][1]['bytes']='malformed'
        self.assertFalse(bv.encrypted_extensions_selected(events,selected))

    def test_target_events_exclude_unrelated_errors(self):
        data=dict(constants=dict(logEventTypes={'URL_REQUEST_START_JOB':1,'SSL_CONNECT':2}),events=[
            dict(type=1,source=dict(id=1),params=dict(url='https://target',source_dependency=dict(id=2))),
            dict(type=2,source=dict(id=2),params=dict(version='TLS 1.3')),
            dict(type=2,source=dict(id=99),params=dict(net_error=-200))])
        selected=bv.relevant_netlog(data,'https://target')
        self.assertEqual(len(selected),2);self.assertNotIn(99,[r[3] for r in selected])

    def test_complete_positive_and_expected_negative_evidence(self):
        import base64
        with tempfile.TemporaryDirectory() as tmp:
            d=Path(tmp);url='https://target'
            server=''.join('>>> TLS 1.3, Handshake [length 0001], '+n+'\n' for n in ('Certificate','CertificateVerify','Finished'))
            (d/'server.log').write_text(server+'<<< TLS 1.3, Handshake [length 0001], Finished\n')
            (d/'chromium.stdout.log').write_text(
                '<html><h1>MTC browser test</h1>'
                '<p id="result">TLS browser validation page</p>'
                'SSL-Session TLS_AES_256_GCM_SHA384</html>'
            )
            (d/'chromium.stderr.log').write_text('')
            def event(name,**params): return dict(type=name,source=dict(id=1),params=params)
            events=[event('URL_REQUEST_START_JOB',url=url),event('SSL_CONNECT',version='TLS 1.3',cipher_suite=0x1302,key_exchange_group=29,is_resumed=False),event('HTTP_TRANSACTION_READ_RESPONSE_HEADERS',headers=['HTTP/1.0 200 ok']),event('SSL_HANDSHAKE_MESSAGE_SENT',type=20)]
            events += [event('SSL_HANDSHAKE_MESSAGE_RECEIVED',type=t) for t in (11,15,20)]
            bv.write(d/'netlog.json',dict(events=events,constants={}))
            requested,selected='32473.200.2.1.1','32473.200.1.1.1'
            self.assertTrue(bv.classify('x509-positive',d,url,0,requested_tai=requested,selected_tai=selected)['pass'])
            self.assertFalse(bv.classify('mtc-no-trust',d,url,0,positive_control=True,requested_tai=requested,selected_tai=selected)['pass'])
            (d/'server.log').write_text('SSL3 alert write:fatal:handshake failure\n')
            (d/'chromium.stdout.log').write_text('certificate error')
            events=[
                event('URL_REQUEST_START_JOB',url=url),
                event('SSL_CONNECT',net_error=-113),
            ]
            (d/'netlog.json').write_text(json.dumps(dict(events=events,constants={})))
            self.assertTrue(bv.classify('mtc-no-trust',d,url,0,positive_control=True,requested_tai=requested,selected_tai=selected)['pass'])
            self.assertFalse(bv.classify('mtc-no-trust',d,url,0,positive_control=False,requested_tai=requested,selected_tai=selected)['pass'])

    def test_unrelated_errors_never_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            d=Path(tmp)
            for name in ('server.log','chromium.stdout.log','chromium.stderr.log'): (d/name).write_text('')
            bv.write(d/'netlog.json',dict(events=[],constants={}))
            result=bv.classify('mtc-no-trust',d,'https://'+bv.HOST,0,positive_control=True,
                               requested_tai='32473.200.2.1.1',selected_tai='32473.200.1.1.1')
            self.assertFalse(result['pass']);self.assertEqual(result['observed_outcome'],'INCONCLUSIVE')


if __name__ == '__main__': unittest.main()

"""Only tiny handcrafted trees, parser checks and synthetic audit fixtures."""
import copy
import csv
import hashlib
import json
from pathlib import Path
import struct
import tempfile
import unittest

from formats import FormatError, MODES, NodeKey, decode, encode, uint, universe
from core import (decode_mtp1, encode_advertisement, encode_mtp2, leaf_hash,
                  parent_hash, verify_mtp2)
from lab import (config_read, configurations, csv_write, digest, json_write,
                 observations, stage_a_seed)
from audit import audit
from analysis import decision

ALL = ['baseline']+list(MODES)


def tiny_tree(n=4):
    credentials=[f'handcrafted-{i}'.encode() for i in range(n)]
    levels=[[leaf_hash(c) for c in credentials]]
    while len(levels[-1])>1:
        old=levels[-1]
        levels.append([parent_hash(old[i],old[min(i+1,len(old)-1)]) for i in range(0,len(old),2)])
    root=levels[-1][0]
    proofs=[]
    for leaf in range(n):
        pos=leaf; siblings=[]
        for level in levels[:-1]:
            siblings.append(level[pos-1 if pos&1 else min(pos+1,len(level)-1)])
            pos//=2
        proofs.append(decode_mtp1(b'MTP1'+struct.pack('!II',n,leaf)+root+bytes([len(siblings)])+b''.join(siblings)))
    return credentials,proofs,root


class FormatTests(unittest.TestCase):
    def setUp(self):
        self.root=hashlib.sha256(b'format-only').digest()

    def test_roundtrips(self):
        # N=1024 exercises coordinates only; no large tree or workload is built.
        for n in (4,8,7,1024):
            nodes=universe(n,self.root)
            for keys in ((),nodes[:1],nodes[-1:],nodes[:3]+nodes[-2:],nodes):
                for scheme in ALL:
                    with self.subTest(n=n,scheme=scheme,count=len(keys)):
                        data=encode(scheme,n,self.root,keys)
                        self.assertEqual(decode(data,n,self.root,scheme),frozenset(keys))
                        self.assertEqual(data,encode(scheme,n,self.root,tuple(reversed(keys))))
                        if scheme=='baseline':
                            self.assertEqual(len(data),38+5*len(keys))
                            self.assertEqual(data,encode_advertisement(self.root,keys))

    def test_every_small_state(self):
        nodes=universe(4,self.root)
        for mask in range(1<<len(nodes)):
            keys=[k for i,k in enumerate(nodes) if mask & (1<<i)]
            for scheme in ALL:
                self.assertEqual(decode(encode(scheme,4,self.root,keys),4,self.root,scheme),frozenset(keys))
            hybrid=encode('hybrid',4,self.root,keys)
            self.assertEqual(len(hybrid),1+min(len(encode(s,4,self.root,keys)) for s in ('coordinates','bitmap','trimmed-bitmap','ranges')))

    def test_negative(self):
        keys=universe(8,self.root)[:3]
        for scheme in ALL:
            data=encode(scheme,8,self.root,keys)
            for cut in range(len(data)):
                with self.assertRaises(FormatError):
                    decode(data[:cut],8,self.root,scheme)
            for bad in (data+b'\0',b'BAD!'+data[4:]):
                with self.assertRaises(FormatError):decode(bad,8,self.root,scheme)
            with self.assertRaises(FormatError):decode(data,8,b'x'*32,scheme)
            for invalid in ((keys[0],keys[0]),(NodeKey(self.root,20,0),),(NodeKey(self.root,0,8),),(NodeKey(b'x'*32,0,0),)):
                with self.assertRaises(FormatError):encode(scheme,8,self.root,invalid)
            if scheme!='baseline':
                with self.assertRaises(FormatError):decode(data,4,self.root,scheme)
                for offset in (4,5):
                    bad=bytearray(data);bad[offset]=255
                    with self.assertRaises(FormatError):decode(bytes(bad),8,self.root,scheme)
        for level,index in ((3,0),(0,8)):
            bad=b'PCA1'+self.root+b'\0\1'+struct.pack('!BI',level,index)
            with self.assertRaises(FormatError):decode(bad,8,self.root,'baseline')

    def test_noncanonical_bodies(self):
        # n=4 header has 39 bytes; all malformed bodies must fail closed.
        bodies={'coordinates':[b'\2\0\0',b'\2\1\0',b'\1\x80\0',b'\1\6',b'\xff\xff\xff'],
                'bitmap':[b'\x80'], 'trimmed-bitmap':[b'\1\0',b'\2\1\0'],
                'ranges':[b'\1\0\0',b'\2\0\1\1\1',b'\2\0\2\1\1',b'\1\5\2'],
                'hybrid':[b'\xff',b'\4\0']}
        for scheme,values in bodies.items():
            header=encode(scheme,4,self.root,())[:39]
            for value in values:
                with self.subTest(scheme=scheme,value=value):
                    with self.assertRaises(FormatError):decode(header+value,4,self.root,scheme)

    def test_baseline_duplicate_decoder_and_header_integer(self):
        entry=struct.pack('!BI',0,0)
        with self.assertRaises(FormatError):
            decode(b'PCA1'+self.root+b'\0\2'+entry+entry,4,self.root,'baseline')
        wire=encode('coordinates',4,self.root,())
        with self.assertRaises(FormatError):
            decode(wire[:38]+b'\x84\0'+wire[39:],4,self.root,'coordinates')

    def test_local_cache_security(self):
        credentials,proofs,root=tiny_tree()
        wire,_=encode_mtp2(proofs[0],set())
        known=verify_mtp2(credentials[0],wire,{},root)
        partial,_=encode_mtp2(proofs[1],set(known))
        for cache,trusted in (({},root),(known,b'x'*32),({k:b'x'*32 for k in known},root)):
            with self.assertRaises(FormatError):verify_mtp2(credentials[1],partial,cache,trusted)


class LaboratoryTests(unittest.TestCase):
    def test_seed_and_config(self):
        c=config_read(); configs=configurations(c)
        self.assertEqual(len(configs),144)
        self.assertEqual(len(configs)*len(c['schemes'])*c['accesses'],720000)
        self.assertEqual(configs[12]['seed'],20260911+14)
        self.assertEqual(configs[-1]['seed'],20260911+155)
        self.assertEqual(stage_a_seed(64,'uniform','lru',0,100,False),137)

    def test_tiny_paired_learning(self):
        # Four accesses on N=4/8 only. No disk fixtures or campaign driver.
        from workloads import generate
        for n in (4,8):
            for policy in ('lru','upper-level'):
                for budget in (0,138,1024):
                    cfg=dict(tree_size=n,workload='uniform',cache_policy=policy,cache_budget_bytes=budget,seed=17)
                    rows=list(observations(*tiny_tree(n),[0,1,0,n-1],cfg,ALL))
                    self.assertEqual(len(rows),4*len(ALL))
                    for t in range(1,5):
                        peers=[r for r in rows if r['access_t']==t]
                        self.assertEqual(len({r['partial_proof_sha256'] for r in peers}),1)
                        self.assertEqual(len({r['state_sha256'] for r in peers}),1)
                        self.assertTrue(all(r['cache_bytes']<=budget for r in peers))
                    self.assertEqual(generate('uniform',n,4,17),generate('uniform',n,4,17))

    def test_matches_stage_a_on_handcrafted_tree(self):
        from unittest.mock import patch
        import run as stage_a
        from workloads import generate
        for policy in ('lru','upper-level'):
            fixture=tiny_tree(4)
            cfg=dict(tree_size=4,workload='uniform',cache_policy=policy,cache_budget_bytes=138,seed=17)
            with patch.object(stage_a,'load_fixture',return_value=fixture), patch.object(stage_a,'git_commit',return_value='unit-test'):
                old=stage_a.simulate(Path('unused'),4,'uniform',4,17,policy,138)
            new=list(observations(*fixture,generate('uniform',4,4,17),cfg,['baseline']))
            mapping={'leaf_id':'leaf_id','reused_hashes':'reused_hashes','transmitted_hashes':'transmitted_hashes',
                     'normal_proof_bytes':'normal_proof_bytes','partial_proof_bytes':'pcma_proof_bytes',
                     'advertisement_bytes':'state_advertisement_bytes','cached_nodes':'cached_nodes',
                     'cache_bytes':'cache_bytes','net_bytes_saved':'net_bytes_saved'}
            for a,b in zip(new,old):
                for key,previous in mapping.items():
                    self.assertEqual(a[key],b[previous])

    def test_cli_and_output_guard(self):
        import contextlib
        import io
        from unittest.mock import patch
        from cli import main
        from lab import execute
        with patch('cli.execute',side_effect=AssertionError('must not execute')):
            with contextlib.redirect_stdout(io.StringIO()) as out:
                main([])
            self.assertIn('--full',out.getvalue())
        with tempfile.TemporaryDirectory(prefix='pcma-a2-guard-') as tmp:
            with self.assertRaises(FileExistsError):
                execute(Path(tmp),Path('must-not-read'),{},[])

    def test_audit_failures(self):
        # Handwritten N=16 accounting rows, no N=16 simulation. Marked single scope.
        from workloads import generate
        c=config_read();c.update(execution='single',accesses=1,base_seed=17,schemes=['baseline','coordinates'])
        cfg=dict(tree_size=16,workload='uniform',cache_policy='lru',cache_budget_bytes=0,seed=17)
        leaf=generate('uniform',16,1,17)[0]
        rows=[]
        for scheme,ad in [('baseline',38),('coordinates',40)]:
            rows.append(dict(cfg,access_t=1,leaf_id=leaf,advertisement_scheme=scheme,normal_proof_hashes=4,
                reused_hashes=0,transmitted_hashes=4,normal_proof_bytes=173,partial_proof_bytes=175,
                advertisement_bytes=ad,net_authentication_bytes=175+ad,gross_proof_bytes_saved=-2,
                net_bytes_saved=-2-ad,net_saving_percentage=100*(-2-ad)/173,advertised_nodes=0,
                advertised_cache_bytes=0,cached_nodes=0,cache_bytes=0,state_sha256='synthetic',
                partial_proof_sha256='synthetic',encoding_applicable=True,
                advertisement_bytes_per_cached_node=None,advertisement_bytes_per_reusable_node=None,
                advertisement_efficiency=-2/ad,encode_time_ns=0,decode_time_ns=0,
                proof_construction_time_ns=0,verification_or_reconstruction_time_ns=0))
        def check(data,expected_failure=False):
            with tempfile.TemporaryDirectory(prefix='pcma-a2-unit-') as tmp:
                d=Path(tmp);csv_write(d/'observations.csv',data)
                json_write(d/'sequences.json',[dict(cfg,leaves=[leaf])])
                json_write(d/'manifest.json',dict(format='pcma-stage-a2-v1',configuration=c,configurations=[cfg],
                    expected_configurations=2,expected_observations=2,
                    output_sha256={k:digest(d/k) for k in ('observations.csv','sequences.json')}))
                if expected_failure:
                    with self.assertRaises(ValueError):audit(d)
                else:
                    self.assertEqual(audit(d)['status'],'PASS')
                    from analysis import aggregate, tables
                    aggregate(d,d/'analysis')
                    tables(d,d/'tables')
                    self.assertTrue((d/'analysis/pareto.csv').is_file())
                    self.assertTrue((d/'tables/all_configurations.tex').is_file())
        check(rows)
        check(rows[:1],True)
        check(rows+[rows[0]],True)
        for field,value in [('net_bytes_saved',123),('leaf_id',99),('seed',18),('cache_bytes',69),('partial_proof_sha256','changed')]:
            bad=copy.deepcopy(rows);bad[1][field]=value;check(bad,True)

    def test_decision_scope(self):
        c=config_read();c['execution']='single'
        self.assertEqual(decision([],c)['outcome'],'INCOMPLETE_SCOPE')
        c['execution']='full'
        self.assertEqual(decision([],c)['outcome'],'NO-GO')

    def test_decision_witnesses(self):
        c=config_read();c['execution']='full'
        rows=[]
        for n in ('256','1024'):
            for w in ('uniform','zipf','clustered'):
                for scheme in ('baseline','coordinates'):
                    rows.append(dict(tree_size=n,workload=w,cache_policy='lru',cache_budget_bytes='1024',seed='17',
                        advertisement_scheme=scheme,mean_advertisement_bytes=100 if scheme=='baseline' else 20,
                        mean_net_bytes_saved=-50 if scheme=='baseline' else 30,
                        mean_net_saving_percentage=-10 if scheme=='baseline' else 15))
        result=decision(rows,c)
        self.assertEqual(result['outcome'],'GO')
        self.assertTrue(result['strong_go'])
        rows=[r for r in rows if r['workload']!='uniform']
        self.assertEqual(decision(rows,c)['outcome'],'NO-GO')


if __name__=='__main__':
    unittest.main(verbosity=2)

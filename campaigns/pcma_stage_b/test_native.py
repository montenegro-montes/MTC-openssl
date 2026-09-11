"""Native/Python equivalence, no sockets and no experimental fixtures."""
import ctypes as C
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'campaigns/pcma_stage_a2'))
from formats import encode, universe
from test_stage_a2 import tiny_tree
from core import NodeKey, encode_mtp2, verify_mtp2, proof_nodes
from cache import NodeCache

class Hash(C.Structure): _fields_=[('bytes',C.c_ubyte*32)]
class Tree(C.Structure): _fields_=[('leaves',C.c_uint),('root',Hash)]
class Proof(C.Structure): _fields_=[('tree',Tree),('index',C.c_uint),('depth',C.c_uint),('siblings',Hash*20)]
class Node(C.Structure): _fields_=[('id',C.c_uint),('hash',Hash)]
class Cache(C.Structure): _fields_=[('tree',Tree),('budget',C.c_uint),('policy',C.c_uint),('count',C.c_uint),('nodes',Node*2046)]
class Metrics(C.Structure):
    _fields_=[(x,C.c_uint) for x in 'advertised proof_bytes credential_bytes normal reused sent hits misses added evicted cache_nodes cache_bytes'.split()]+[(x,C.c_double) for x in 'encode_ms parse_ms range_ms construct_ms lookup_ms reconstruct_ms verify_ms credential_verify_ms'.split()]

class NativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory(prefix='pcma-b-unit-')
        prefix=Path(os.environ.get('OPENSSL_PREFIX','/opt/openssl'))
        libdir=prefix/'lib'
        if not libdir.exists():libdir=prefix/'lib64'
        target=Path(cls.tmp.name)/'protocol.so'
        subprocess.run(['cc','-std=c11','-shared','-fPIC','-O1','-Wall','-Wextra','-Werror',
            '-Wno-misleading-indentation','-Wno-unused-function','-I'+str(prefix/'include'),'-I'+str(ROOT/'integration'),
            '-I'+str(ROOT/'codigoOriginal/C/crypto'),str(ROOT/'campaigns/pcma_stage_b/native/protocol.c'),
            str(ROOT/'integration/mt_wire.c'),str(ROOT/'codigoOriginal/C/crypto/merkle.c'),
            '-L'+str(libdir),'-Wl,-rpath,'+str(libdir),'-lcrypto','-o',str(target)],check=True)
        cls.lib=C.CDLL(str(target))
        cls.lib.pc_encode.argtypes=[C.POINTER(Cache),C.c_void_p,C.c_size_t,C.POINTER(C.c_size_t)]
        cls.lib.pc_decode.argtypes=[C.c_void_p,C.c_size_t,C.POINTER(Tree),C.c_void_p]
        cls.lib.pc_partial.argtypes=[C.POINTER(Proof),C.c_void_p,C.c_void_p,C.c_size_t,C.POINTER(C.c_size_t),C.POINTER(Metrics)]
        cls.lib.pc_reconstruct.argtypes=[C.c_void_p,C.c_size_t,C.POINTER(Cache),C.POINTER(Proof),C.POINTER(Metrics)]
        cls.lib.pc_learn.argtypes=[C.POINTER(Cache),C.c_void_p,C.c_size_t,C.POINTER(Proof),C.POINTER(Metrics)]
        cls.lib.pc_load.argtypes=[C.POINTER(Cache),C.c_char_p]
        cls.lib.pc_save.argtypes=[C.POINTER(Cache),C.c_char_p]
    @classmethod
    def tearDownClass(cls):cls.tmp.cleanup()
    def cache(self,n,root,budget=2048,policy=0):
        c=Cache();c.tree.leaves=n;c.tree.root.bytes[:]=root;c.budget=budget;c.policy=policy;return c
    def nativeproof(self,p):
        q=Proof();q.tree.leaves=p.leaves;q.tree.root.bytes[:]=p.root;q.index=p.leaf_index;q.depth=len(p.siblings)
        for i,h in enumerate(p.siblings):q.siblings[i].bytes[:]=h
        return q
    def encoded(self,c):
        out=C.create_string_buffer(8192);n=C.c_size_t()
        self.assertEqual(self.lib.pc_encode(C.byref(c),out,len(out),C.byref(n)),1)
        return out.raw[:n.value]
    def test_roundtrips_and_max_coordinates(self):
        root=b'a'*32
        for n in (4,8,1024):
            nodes=universe(n,root)
            for ids in ([],[0],[len(nodes)-1],list(range(len(nodes)))):
                c=self.cache(n,root,budget=69*2046);c.count=len(ids)
                for i,j in enumerate(ids):c.nodes[i].id=j
                wire=self.encoded(c)
                self.assertEqual(wire,encode('ranges',n,root,[nodes[i] for i in ids]))
                selected=C.create_string_buffer(2046)
                self.assertEqual(self.lib.pc_decode(wire,len(wire),C.byref(c.tree),selected),1)
                self.assertEqual([i for i,b in enumerate(selected.raw) if b],ids)
    def test_paired_cache_and_proofs(self):
        for n in (4,8):
            credentials,proofs,root=tiny_tree(n)
            for policy in (0,1):
                for budget in (0,138,2048):
                    c=self.cache(n,root,budget,policy);model=NodeCache(budget,'upper-level' if policy else 'lru')
                    nodes=universe(n,root)
                    for leaf in (0,1,2,n-1,0):
                        wire=self.encoded(c);self.assertEqual(wire,encode('ranges',n,root,model.advertised_keys(root)))
                        selected=C.create_string_buffer(2046);self.assertTrue(self.lib.pc_decode(wire,len(wire),C.byref(c.tree),selected))
                        q=self.nativeproof(proofs[leaf]);m=Metrics();out=C.create_string_buffer(8192);length=C.c_size_t()
                        self.assertTrue(self.lib.pc_partial(C.byref(q),selected,out,len(out),C.byref(length),C.byref(m)))
                        partial=out.raw[:length.value];expected,sent=encode_mtp2(proofs[leaf],set(model.advertised_keys(root)))
                        self.assertEqual(partial,expected);self.assertEqual(m.sent,sent)
                        reconstructed=Proof();self.assertTrue(self.lib.pc_reconstruct(partial,len(partial),C.byref(c),C.byref(reconstructed),C.byref(m)))
                        self.assertTrue(self.lib.pc_learn(C.byref(c),credentials[leaf],len(credentials[leaf]),C.byref(reconstructed),C.byref(m)))
                        model.account(proof_nodes(proofs[leaf]));authenticated=verify_mtp2(credentials[leaf],expected,model.values(),root)
                        model.update({k:v for k,v in authenticated.items() if k.level<len(proofs[leaf].siblings)})
                        self.assertEqual([(nodes[c.nodes[i].id],bytes(c.nodes[i].hash.bytes)) for i in range(c.count)],list(model.values().items()))
    def test_negative_parsers_and_trust(self):
        credentials,proofs,root=tiny_tree(4);c=self.cache(4,root);wire=self.encoded(c);selected=C.create_string_buffer(2046)
        bad=[wire[:i] for i in range(len(wire))]+[wire+b'\0',wire[:4]+b'\2'+wire[5:],wire[:5]+b'\5'+wire[6:],wire[:6]+b'x'*32+wire[38:],wire[:38]+b'\x84\0'+wire[39:],wire[:39]+b'\2\0\1\1\1']
        for data in bad:self.assertFalse(self.lib.pc_decode(data,len(data),C.byref(c.tree),selected))
        normal,_=encode_mtp2(proofs[0],set());q=Proof();m=Metrics()
        for data in [normal[:i] for i in range(len(normal))]+[normal+b'\0',normal[:12]+b'x'*32+normal[44:],normal[:46]+bytes([normal[46]|1])+normal[47:]]:
            self.assertFalse(self.lib.pc_reconstruct(data,len(data),C.byref(c),C.byref(q),C.byref(m)))
        self.assertTrue(self.lib.pc_reconstruct(normal,len(normal),C.byref(c),C.byref(q),C.byref(m)))
        before=bytes(c);self.assertFalse(self.lib.pc_learn(C.byref(c),b'wrong-credential',16,C.byref(q),C.byref(m)));self.assertEqual(before,bytes(c))
        self.assertTrue(self.lib.pc_learn(C.byref(c),credentials[0],len(credentials[0]),C.byref(q),C.byref(m)))
        partial,_=encode_mtp2(proofs[1],set(universe(4,root)[c.nodes[i].id] for i in range(c.count)))
        empty=self.cache(4,root)
        self.assertFalse(self.lib.pc_reconstruct(partial,len(partial),C.byref(empty),C.byref(q),C.byref(m)))
        for i in range(c.count):c.nodes[i].hash.bytes[:]=b'x'*32
        self.assertTrue(self.lib.pc_reconstruct(partial,len(partial),C.byref(c),C.byref(q),C.byref(m)))
        self.assertFalse(self.lib.pc_learn(C.byref(c),credentials[1],len(credentials[1]),C.byref(q),C.byref(m)))
    def test_persistence_binding(self):
        credentials,proofs,root=tiny_tree(4);c=self.cache(4,root);q=self.nativeproof(proofs[0]);m=Metrics()
        self.assertTrue(self.lib.pc_learn(C.byref(c),credentials[0],len(credentials[0]),C.byref(q),C.byref(m)))
        path=Path(self.tmp.name)/'state.bin';self.assertTrue(self.lib.pc_save(C.byref(c),os.fsencode(path)))
        restored=self.cache(4,root);self.assertTrue(self.lib.pc_load(C.byref(restored),os.fsencode(path)));self.assertEqual(self.encoded(c),self.encoded(restored))
        for invalid in (self.cache(4,b'x'*32),self.cache(4,root,4096),self.cache(4,root,2048,1)):
            self.assertFalse(self.lib.pc_load(C.byref(invalid),os.fsencode(path)))
        path.write_bytes(path.read_bytes()+b'\0');self.assertFalse(self.lib.pc_load(C.byref(restored),os.fsencode(path)))

if __name__=='__main__':unittest.main(verbosity=2)

"""Inexpensive deterministic and negative PCMA format tests."""
import hashlib,struct
from cache import NodeCache
from core import FormatError,NodeKey,decode_advertisement,decode_mtp1,encode_advertisement,encode_mtp2,leaf_hash,parent_hash,proof_nodes,verify_mtp1,verify_mtp2

def fixtures(n=16):
    credentials=[f"credential-{i}".encode() for i in range(n)];levels=[[leaf_hash(x) for x in credentials]]
    while len(levels[-1])>1:
        old=levels[-1];levels.append([parent_hash(old[i],old[min(i+1,len(old)-1)]) for i in range(0,len(old),2)])
    root=levels[-1][0];proofs=[]
    for index in range(n):
        pos=index;siblings=[]
        for level in levels[:-1]:siblings.append(level[pos-1 if pos&1 else min(pos+1,len(level)-1)]);pos//=2
        proofs.append(decode_mtp1(b"MTP1"+struct.pack("!II",n,index)+root+bytes([len(siblings)])+b"".join(siblings)))
    return credentials,proofs,root

credentials,proofs,root=fixtures();known=verify_mtp1(credentials[0],proofs[0]);available=set(known)
partial,transmitted=encode_mtp2(proofs[1],available);assert transmitted<4
verified=verify_mtp2(credentials[1],partial,known,root);assert verified
advertisement=encode_advertisement(root,list(known));assert decode_advertisement(advertisement)[0]==root
cache=NodeCache(2*69,"upper-level");cache.update(known);assert cache.bytes<=138 and all(k.root==root for k in cache.values())
for corrupt_cache,corrupt_root,corrupt_data in [({},root,partial),(known,hashlib.sha256(root).digest(),partial),(known,root,partial[:-1])]:
    try:verify_mtp2(credentials[1],corrupt_data,corrupt_cache,corrupt_root)
    except FormatError:pass
    else:raise AssertionError("malformed/cross-root MTP2 accepted")
other_root=hashlib.sha256(b"other").digest();assert not any(NodeKey(other_root,k.level,k.index) in known for k in proof_nodes(proofs[1]))
try:decode_advertisement(advertisement+b"\0")
except FormatError:pass
else:raise AssertionError("trailing PCA1 data accepted")
print("PASS deterministic MTP2/PCA1 round trips and negative checks")

#!/usr/bin/env python3
from trusted_subtrees import TrustedSubtree, encode_trusted_subtrees, decode_trusted_subtrees

items=[TrustedSubtree(1,0,4,bytes.fromhex("11"*32))]
data=encode_trusted_subtrees(items)
assert data[:4]==b"MTS1"
assert decode_trusted_subtrees(data)==items
print("PASS: MTS1 trusted subtree encoding")

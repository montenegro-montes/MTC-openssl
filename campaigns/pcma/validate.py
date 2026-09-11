"""Lightweight structural validation of a PCMA fixture manifest."""
import argparse, json
from pathlib import Path
from core import decode_mtp1, verify_mtp1


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("--fixtures",type=Path,required=True);a=p.parse_args();m=json.loads(a.fixtures.read_text())
    assert m["format"]=="pcma-fixture-manifest-v1"
    for text,entry in m["sizes"].items():
        n=int(text);directory=Path(entry["directory"]);root=bytes.fromhex(entry["tree_root_sha256"])
        for i in {0,n//2,n-1}:
            credential=(directory/f"credential-{i:04d}.bin").read_bytes();proof=decode_mtp1((directory/f"proof-{i:04d}.bin").read_bytes())
            assert proof.leaves==n and proof.leaf_index==i and proof.root==root;verify_mtp1(credential,proof)
    print("PASS",a.fixtures)


if __name__=="__main__":main()

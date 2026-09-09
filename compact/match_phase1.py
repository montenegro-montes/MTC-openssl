"""Add a phase-1 tree over the same certificate population; never replace old trees."""
import argparse
from pathlib import Path
import json
import struct
import subprocess
from prepare import command, tree

def ensure(batch, scenario):
    directory = batch / scenario
    info = json.loads((directory/'manifest.json').read_text())
    certificates = [Path('/work/certs')/scenario/'server.pem'] + [directory/'issued'/f'{i}.pem' for i in range(1, info['leaves'])]
    values = [command('x509','-in',cert,'-outform','DER') for cert in certificates]
    root, proofs = tree(values)
    destination = directory/'x509-merkle'
    if not destination.exists():
        subprocess.run(['/opt/mt/bin/mt_bundle',str(destination),*map(str,certificates)],check=True)
    if (destination/'root.bin').read_bytes() != b'MTR1'+struct.pack('!I',info['leaves'])+root:
        raise RuntimeError('Existing phase-1 root does not match this batch; preserved, not overwritten')
    for i, proof in enumerate(proofs):
        if (destination/f'proof-{i:04d}.bin').read_bytes() != proof:
            raise RuntimeError('Existing proof differs; preserved, not overwritten')
    print('Matched phase-1 tree:',scenario,info['leaves'],flush=True)

if __name__ == '__main__':
    p=argparse.ArgumentParser();p.add_argument('batch',type=Path);a=p.parse_args()
    for scenario in ['classic','pq']: ensure(a.batch,scenario)

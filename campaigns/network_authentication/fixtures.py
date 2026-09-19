"""Manual, network-disabled fixture preparation. Default prints a plan only."""
import argparse
import os
from pathlib import Path
import subprocess
import sys

from .common import REPO, OPENSSL, LIBS, image_id, protocol, save, sha, source_inventory, git_metadata, require


def build(output):
    """Runs only inside the explicitly started preparation container."""
    sys.path.insert(0, str(REPO / 'src/mtc'))
    import prepare
    prepare.OPENSSL = OPENSSL
    output.mkdir()  # never reuse or overwrite
    os.umask(0o077)
    def ossl(*args):
        result = subprocess.run([OPENSSL, *map(str, args)], capture_output=True, text=True)
        require(result.returncode == 0, 'OpenSSL fixture command failed: ' + result.stderr[-1500:])
    def key(path, profile):
        args = ['genpkey', '-algorithm', 'EC' if profile == 'ecdsa-p256' else 'mldsa65']
        if profile == 'ecdsa-p256':
            args += ['-pkeyopt', 'ec_paramgen_curve:P-256']
        ossl(*args, '-out', path)
    for profile, sizes in protocol()['profiles'].items():
        for role in ['server', 'client']:
            root = output / profile / role
            root.mkdir(parents=True)
            digest = ['-sha256'] if profile == 'ecdsa-p256' else []
            key(root / 'ca.key', profile)
            ossl('req', '-new', '-x509', '-key', root / 'ca.key', '-out', root / 'ca.pem',
                 '-days', '3650', '-subj', f'/CN=Network Authentication {profile} {role} CA',
                 '-addext', 'basicConstraints=critical,CA:TRUE',
                 '-addext', 'keyUsage=critical,keyCertSign,cRLSign', *digest)
            ext = root / 'leaf.ext'
            ext.write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n'
                           f'extendedKeyUsage={role}Auth\nsubjectAltName=DNS:{role}\n'
                           'subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n')
            originals = []
            for i in range(max(sizes)):
                stem = root / f'leaf-{i:04d}'
                key(stem.with_suffix('.key'), profile)
                ossl('req', '-new', '-key', stem.with_suffix('.key'), '-out', stem.with_suffix('.csr'),
                     '-subj', f'/CN={role}', *digest)
                ossl('x509', '-req', '-in', stem.with_suffix('.csr'), '-CA', root / 'ca.pem',
                     '-CAkey', root / 'ca.key', '-set_serial', str(i + 1), '-days', '3650',
                     '-extfile', ext, '-out', stem.with_suffix('.pem'), *digest)
                originals.append(stem.with_suffix('.pem'))
            # Dedicated MTC signer keys, distinct from the X.509 CA; held fixed across N.
            signers = [root / f'mtc-signer-{i}.key' for i in range(2)]
            for signer in signers:
                key(signer, profile)
            for n in sizes:
                prepare.prepare(root / f'mtc-n{n}', root, profile, n, originals=originals[:n],
                                signer_keys=signers, metadata={'experiment': protocol()['experiment'],
                                'role': role, 'source_chain_profile': 'ca-server',
                                'baseline_leaf_sha256': sha(originals[0])})
    save(output / 'preparation-status.json', {'passed': True, 'tls_executed': False})


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', type=Path)
    p.add_argument('--image')
    p.add_argument('--execute', action='store_true')
    p.add_argument('--inside', type=Path, help=argparse.SUPPRESS)
    a = p.parse_args()
    if a.inside:
        build(a.inside)
        return
    require(a.output is not None and a.image is not None, '--output and --image are required')
    output = a.output.resolve()
    require(output.is_relative_to(REPO / 'artifacts/network-authentication'), 'Use artifacts/network-authentication/...')
    require(not output.exists(), 'Output exists: choose a fresh fixture root')
    image = image_id(a.image)
    cmd = ['docker', 'run', '--rm', '--network', 'none', '-e', f'LD_LIBRARY_PATH={LIBS}',
           '-e', 'PYTHONDONTWRITEBYTECODE=1', '-v', f'{REPO}:/repo:ro',
           '-v', f'{output.parent}:/output', '-w', '/repo', '--entrypoint', 'python3', image,
           '-m', 'campaigns.network_authentication.fixtures', '--inside', f'/output/{output.name}']
    if not a.execute:
        import json
        print(json.dumps({'execute': False, 'command': cmd}, indent=2)); return
    before = source_inventory()
    git = git_metadata()
    output.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(cmd, check=True)
    require(before == source_inventory(), 'Source changed during fixture preparation')
    save(output / 'provenance.json', {'image_id': image, 'git': git, 'source_sha256': before})
    print(output)


if __name__ == '__main__':
    main()

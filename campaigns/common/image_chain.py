"""Resolve and, when necessary, rebuild the local TLS image chain."""
import argparse
import json
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SPECS = {
    'lab': ('mt-tls-lab:local', 'docker/original_campaigns/Dockerfile', None),
    'compact': ('mt-tls-compact:local', 'docker/original_campaigns/Dockerfile.compact', 'lab'),
    'profile': ('mt-tls-profile:local', 'docker/original_campaigns/Dockerfile.profile', 'compact'),
    'mtc': ('mt-tls-mtc:local', 'docker/original_campaigns/Dockerfile.mtc', 'profile'),
    'measurement': ('mt-tls-measurement:local', 'docker/original_campaigns/Dockerfile.measurement', 'mtc'),
    'network': ('mt-tls-network:latency', 'docker/original_campaigns/Dockerfile.network', 'measurement'),
}

def inspect(reference):
    result = subprocess.run(['docker', 'image', 'inspect', reference], text=True, capture_output=True)
    return json.loads(result.stdout)[0] if result.returncode == 0 else None

def derived_from(image, parent):
    child_layers = image['RootFS']['Layers']
    parent_layers = parent['RootFS']['Layers']
    return child_layers[:len(parent_layers)] == parent_layers

def ensure(target='network'):
    if target not in SPECS:
        raise ValueError(f'Unknown image target: {target}')
    images = {}; rebuilt = []
    def resolve(name):
        tag, dockerfile, parent_name = SPECS[name]
        parent = resolve(parent_name) if parent_name else None
        image = inspect(tag)
        reason = None
        if image is None:
            reason = 'missing'
        elif parent is not None and not derived_from(image, parent):
            reason = 'base image changed'
        if reason:
            command = ['docker', 'build', '-f', dockerfile, '-t', tag]
            if name == 'measurement':
                command += ['--build-arg', f'BASE_IMAGE={SPECS[parent_name][0]}']
            command += ['.']
            subprocess.run(command, cwd=REPO, check=True)
            image = inspect(tag)
            if image is None:
                raise RuntimeError(f'Build did not create {tag}')
            if parent is not None and not derived_from(image, parent):
                raise RuntimeError(f'{tag} is not derived from {SPECS[parent_name][0]}')
            rebuilt.append({'name':name, 'tag':tag, 'reason':reason, 'image_id':image['Id']})
        images[name] = image
        return image
    target_image = resolve(target)
    return {'target':target_image, 'images':images, 'rebuilt':rebuilt}

def main():
    parser=argparse.ArgumentParser(description='Ensure a validated local TLS image dependency chain exists.')
    parser.add_argument('target',choices=SPECS,default='network',nargs='?')
    args=parser.parse_args();result=ensure(args.target)
    print(json.dumps({'target':args.target,'target_image_id':result['target']['Id'],
        'image_ids':{name:image['Id'] for name,image in result['images'].items()},
        'automatic_rebuilds':result['rebuilt']},indent=2))

if __name__=='__main__':main()

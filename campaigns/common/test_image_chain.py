"""Unit checks for missing-image restoration and parent validation."""
from unittest.mock import patch
from campaigns.common import image_chain

def fake_image(name, layers):
    return {'Id':'sha256:'+name, 'RootFS':{'Layers':layers}}

images={
    'mt-tls-lab:local':fake_image('lab',['lab']),
    'mt-tls-mtc:local':fake_image('mtc',['lab','mtc']),
    'mt-tls-network-measurement:local':fake_image('measurement',['lab','mtc','measurement']),
    'mt-tls-network:local':None,
}
commands=[]
def inspect(reference):return images[reference]
def run(command,**kwargs):
    commands.append(command)
    images['mt-tls-network:local']=fake_image('network',['lab','mtc','measurement','network'])

with patch.object(image_chain,'inspect',side_effect=inspect),patch.object(image_chain.subprocess,'run',side_effect=run):
    result=image_chain.ensure('network')
assert len(commands)==1 and commands[0][:4]==['docker','build','-f','docker/network/Dockerfile.network']
assert result['target']['Id']=='sha256:network'
assert result['rebuilt'][0]['reason']=='missing'
print('PASS missing child image is rebuilt and parent layers are verified')

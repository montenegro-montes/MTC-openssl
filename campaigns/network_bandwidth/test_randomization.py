"""The validator must reproduce the driver's single RNG stream."""
import random
from run import SCENARIOS

def orders(seed,warmups,runs):
    rng=random.Random(seed);warm=[];measured=[]
    for output,count in [(warm,warmups),(measured,runs)]:
        for _ in range(count):
            order=SCENARIOS.copy();rng.shuffle(order);output.append(order)
    return warm,measured

warm,measured=orders(250021,3,5)
assert warm[0]==['pq-rpk','pq-compact-cold','pq','pq-mtc-experimental-landmark','pq-compact-warm','pq-mtc-experimental-standalone']
assert measured[0]==['pq-compact-warm','pq-compact-cold','pq-mtc-experimental-landmark','pq-rpk','pq','pq-mtc-experimental-standalone']
assert measured[-1]==['pq-compact-warm','pq-compact-cold','pq-mtc-experimental-standalone','pq-rpk','pq','pq-mtc-experimental-landmark']
print('PASS warmup and measured orders share one deterministic RNG stream')

"""Check pairing and campaign-level resampling independently of observed data."""
import random,statistics
from analyze import paired_effect,bootstrap_campaign,sign_stability,quantile
x={1:0,2:100,3:101};y={1:100,2:0,3:100}
assert paired_effect(x,y)==1
assert statistics.median(x.values())-statistics.median(y.values())==0
try:paired_effect({1:1},{2:1})
except ValueError:pass
else:raise AssertionError('Unpaired rounds accepted')
rng=random.Random(20260910);draws=[rng.choices(range(10),k=10) for _ in range(10000)]
assert bootstrap_campaign([2]*10,draws)==(2,2)
assert bootstrap_campaign([-1]*10,draws)==(-1,-1)
try:bootstrap_campaign([1]*300,draws)
except ValueError:pass
else:raise AssertionError('Pooled handshakes accepted as campaigns')
low,high=bootstrap_campaign([-1]*5+[1]*5,draws)
assert low<0<high
assert sign_stability([-1]*5+[1]*5,low,high).startswith('unstable')
assert sign_stability([-1]*9+[1],-2,1).startswith('uncertain')
assert quantile([0,10],.25)==2.5
assert quantile([0,10],.975)==9.75
print('Analysis checks PASS: paired rounds, ten-campaign resampling, 10000 draws, sign stability, percentile interpolation')

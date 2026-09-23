"""Protect pairing and campaign resampling; no TLS protocol tests duplicated here."""
from analyze import effect,bootstrap,linfit,RESAMPLES,stability
assert effect({1:0,2:100,3:101},{1:0,2:1,3:100})==1
try:effect({1:1},{2:1})
except ValueError:pass
else:raise AssertionError('unpaired data accepted')
assert len(RESAMPLES)==10000 and all(len(r)==5 and all(0<=i<5 for i in r) for r in RESAMPLES)
assert bootstrap([7]*5)==(7,7)
try:bootstrap([7]*150)
except ValueError:pass
else:raise AssertionError('pooled handshakes accepted')
r=linfit([0,2,4,6,8,10],[45,109,173,237,301,365]);assert r['slope']==32 and r['intercept']==45 and r['r_squared']==1
assert stability([-1,-2,1,2,3],-2,3).startswith('uncertain')
print('PASS paired effects, five-campaign bootstrap, no pooled samples, serialized-size slope')

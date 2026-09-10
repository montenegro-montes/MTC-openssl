from analyze import bootstrap
assert bootstrap([3]*5)==(3,3)
lo,hi=bootstrap([-2,-1,0,1,2]);assert lo<=0<=hi
print('PASS five-campaign bootstrap and percentile interval')

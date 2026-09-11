"""Directional iperf output is delimited and errors remain observable."""
import json
from run import GOODPUT_MAX_RATIO,GOODPUT_MIN_RATIO,RTT_ABSOLUTE_TOLERANCE_MS,iperf_result,parse_probe

valid={'intervals':[{'sum':{'bits_per_second':5_000_000,'omitted':True}},{'sum':{'bits_per_second':8_000_000}},{'sum':{'bits_per_second':19_000_000}},{'sum':{'bits_per_second':20_000_000}}],'end':{'sum_received':{'bits_per_second':14_000_000},'sum_sent':{'retransmits':0}}}
text='IPERF_FORWARD_BEGIN\n'+json.dumps(valid)+'\nIPERF_FORWARD_END\n'
assert iperf_result(text,'FORWARD')==valid
assert GOODPUT_MIN_RATIO==.80 and GOODPUT_MAX_RATIO==1.05
assert RTT_ABSOLUTE_TOLERANCE_MS==10.0
ping='\n'.join(f'64 bytes from server: icmp_seq={i} ttl=64 time=50.0 ms' for i in range(1,21))
both=ping+'\nIPERF_FORWARD_BEGIN\n'+json.dumps(valid)+'\nIPERF_FORWARD_END\nIPERF_REVERSE_BEGIN\n'+json.dumps(valid)+'\nIPERF_REVERSE_END\n'
try:parse_probe(both,20)
except RuntimeError as error:assert 'Received goodput' in str(error)
else:raise AssertionError('out-of-range received goodput was accepted')
failed={'error':'unable to receive control message: Connection reset by peer','end':{}}
text='IPERF_REVERSE_BEGIN\n'+json.dumps(failed)+'\nIPERF_REVERSE_END\n'
try:iperf_result(text,'REVERSE')
except RuntimeError as error:assert 'Connection reset by peer' in str(error)
else:raise AssertionError('iperf error was not rejected')
print('PASS directional iperf parser and error reporting')

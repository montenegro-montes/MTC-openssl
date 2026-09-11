"""Directional iperf output is delimited and errors remain observable."""
import json
from run import iperf_result

valid={'end':{'sum_received':{'bits_per_second':20_000_000},'sum_sent':{'retransmits':0}}}
text='IPERF_FORWARD_BEGIN\n'+json.dumps(valid)+'\nIPERF_FORWARD_END\n'
assert iperf_result(text,'FORWARD')==valid
failed={'error':'unable to receive control message: Connection reset by peer','end':{}}
text='IPERF_REVERSE_BEGIN\n'+json.dumps(failed)+'\nIPERF_REVERSE_END\n'
try:iperf_result(text,'REVERSE')
except RuntimeError as error:assert 'Connection reset by peer' in str(error)
else:raise AssertionError('iperf error was not rejected')
print('PASS directional iperf parser and error reporting')

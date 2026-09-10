import json
from network import validate_qdisc,parse_ping,section,counters,delta,qdisc_drops
q='qdisc netem 1: root refcnt 2 limit 1000 delay 25ms loss 0.1%\n Sent 1 bytes 1 pkt (dropped 2, overlimits 0 requeues 0)'
validate_qdisc(q,'0.1');assert qdisc_drops(q)==2
try:validate_qdisc(q+' qdisc tbf','0.1')
except ValueError:pass
else:raise AssertionError('TBF accepted')
text='\n'.join(['64 bytes from server: time=50.0 ms']*199+['200 packets transmitted, 199 received, 0.5% packet loss'])
p=parse_ping(text,200);assert p['probe_packets_received']==199 and p['loss_measured_percent']==.5
s='TCP_CLIENT_BEFORE_BEGIN\nTcpRetransSegs 2\nTcpOutSegs 10\nTcpInSegs 9\nTCP_CLIENT_BEFORE_END'
assert counters(s,'CLIENT_BEFORE')['TcpOutSegs']==10
assert delta({'TcpRetransSegs':2,'TcpOutSegs':10,'TcpInSegs':9},{'TcpRetransSegs':3,'TcpOutSegs':14,'TcpInSegs':12})['tcp_retransmitted_segments']==1
print('PASS decimal loss, no-rate-qdisc guard, probe and TCP counter parsing')

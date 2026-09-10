from config import PROFILES,burst_bytes,seed
from network import commands,own_tbf_drops,parse_iperf,parse_ping,qdisc_kind_drops,validate_qdisc,validate_throughput
assert seed('baseline',1)==400001 and seed('adverse',5)==403005
assert burst_bytes(1)==1600 and burst_bytes(20)==2500
validate_qdisc('qdisc netem 10: root refcnt 2 limit 1000 delay 5ms loss 0%',PROFILES['baseline'])
validate_qdisc('qdisc netem 10: root refcnt 2 limit 1000 delay 5ms',PROFILES['baseline'])
validate_qdisc('qdisc tbf 1: root rate 5Mbit burst 1600b lat 1s\nqdisc netem 10: parent 1:1 limit 1000 delay 50ms loss 1%',PROFILES['constrained'])
try:
    validate_qdisc('qdisc netem 10: root refcnt 2 limit 1000 delay 5ms loss 1%',PROFILES['baseline'])
except ValueError:
    pass
else:
    raise AssertionError('baseline accepted non-zero loss')
try:
    validate_qdisc('qdisc tbf 1: root rate 5Mbit burst 1600b lat 1s\nqdisc netem 10: parent 1:1 limit 1000 delay 50ms',PROFILES['constrained'])
except ValueError:
    pass
else:
    raise AssertionError('non-zero profile accepted omitted loss')
assert len(commands(PROFILES['baseline']))==1 and len(commands(PROFILES['wan']))==2
assert parse_iperf('[SUM] 0-2 sec 4 MBytes 19.7 Mbits/sec receiver')==19.7
assert parse_iperf('[  5] 0.00-2.00 sec 263 MBytes 1.10 Gbits/sec receiver')==1100.0
assert parse_iperf('[  5] 0.00-2.00 sec 125 KBytes 500 Kbits/sec receiver')==0.5
validate_throughput(4.22,5)
validate_throughput(1.0,None)
for measured,configured in [(0,5),(5.76,5)]:
    try: validate_throughput(measured,configured)
    except ValueError: pass
    else: raise AssertionError('invalid throughput accepted')
qdisc='''qdisc tbf 1: root rate 5Mbit\n Sent 1 bytes 1 pkt (dropped 21, overlimits 2 requeues 0)\nqdisc netem 10: parent 1:1 loss 1%\n Sent 1 bytes 1 pkt (dropped 21, overlimits 0 requeues 0)'''
assert own_tbf_drops(qdisc_kind_drops(qdisc))==0
assert own_tbf_drops({'tbf':25,'netem':21})==4
assert parse_ping('2 packets transmitted, 2 received, 0% packet loss\n64 bytes time=9.0 ms\n64 bytes time=11.0 ms',2)['measured_rtt_median_ms']==10
print('PASS network unit tests')

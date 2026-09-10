"""Generate and validate the declared TBF -> netem per-egress hierarchy."""
import re
from config import TBF_QUEUE_LATENCY_MS, burst_bytes

FORBIDDEN = ("jitter", "reorder", "duplicate", "corrupt")
def commands(profile):
    delay=f'{profile["half_delay_ms"]}ms'; loss=f'{profile["loss_percent"]}%'
    if profile["rate_mbit"] is None:
        return [["tc","qdisc","replace","dev","eth0","root","handle","10:","netem","delay",delay,"loss",loss]]
    rate=profile["rate_mbit"]
    return [
      ["tc","qdisc","replace","dev","eth0","root","handle","1:","tbf","rate",f"{rate}mbit","burst",str(burst_bytes(rate)),"latency",f"{TBF_QUEUE_LATENCY_MS}ms"],
      ["tc","qdisc","replace","dev","eth0","parent","1:1","handle","10:","netem","delay",delay,"loss",loss],
    ]
def validate_qdisc(text, profile):
    low=text.lower()
    if any(word in low for word in FORBIDDEN): raise ValueError("forbidden impairment configured")
    if "netem" not in low or f'delay {profile["half_delay_ms"]}ms' not in low: raise ValueError("delay mismatch")
    # iproute2 omits the loss attribute when netem is configured with loss 0%.
    # Accept omission only for the baseline; non-zero profiles must expose the
    # exact configured percentage.
    configured=[float(value) for value in re.findall(r'loss(?: random)?\s+([0-9.]+)%',low)]
    expected=float(profile["loss_percent"])
    if expected==0:
        if any(value!=0 for value in configured): raise ValueError("loss mismatch")
    elif not configured or not any(abs(value-expected)<1e-12 for value in configured):
        raise ValueError("loss mismatch")
    limited=profile["rate_mbit"] is not None
    if limited != (" tbf " in " "+low+" "): raise ValueError("bandwidth hierarchy mismatch")
    if limited and ("parent 1:1" not in low or not re.search(r'rate\s+'+str(profile["rate_mbit"])+r'mbit',low)): raise ValueError("TBF rate/parent mismatch")
def parse_ping(text, sent):
    m=re.search(r'(\d+) packets transmitted, (\d+) received, ([0-9.]+)% packet loss',text)
    if not m or int(m.group(1)) != sent: raise ValueError("invalid ping probe")
    values=sorted(float(x) for x in re.findall(r'time[=<]([0-9.]+) ms',text))
    if not values: raise ValueError("no RTT observations")
    n=len(values); median=values[n//2] if n%2 else (values[n//2-1]+values[n//2])/2
    return {"probe_packets_sent":sent,"probe_packets_received":int(m.group(2)),"loss_measured_percent":float(m.group(3)),"measured_rtt_min_ms":values[0],"measured_rtt_median_ms":median,"measured_rtt_max_ms":values[-1]}
def parse_iperf(text):
    matches=re.findall(r'([0-9.]+)\s+([KMG])bits/sec',text)
    if not matches: raise ValueError("missing iperf throughput")
    value,unit=matches[-1]
    return float(value)*{"K":0.001,"M":1.0,"G":1000.0}[unit]
def section(text,start,end):
    m=re.search(re.escape(start)+r'\n(.*?)'+re.escape(end),text,re.S)
    if not m: raise ValueError("missing section "+start)
    return m.group(1)
def qdisc_kind_drops(text):
    result={}
    for block in re.split(r'(?=qdisc )',text):
        kind=re.search(r'^qdisc\s+(\w+)',block); dropped=re.search(r'dropped\s+(\d+)',block)
        if kind and dropped: result[kind.group(1)]=result.get(kind.group(1),0)+int(dropped.group(1))
    return result

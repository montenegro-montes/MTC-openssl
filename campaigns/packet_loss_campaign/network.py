"""Parsing and validation for tc, ping and campaign-level TCP counters."""
import re
RATE_QDISCS=('tbf','htb','hfsc','cake')
def validate_qdisc(text,loss):
    lower=text.lower()
    if 'netem' not in lower or 'delay 25ms' not in lower:raise ValueError('Expected netem delay 25ms')
    # iproute2 omits the loss attribute when netem is configured with loss 0%.
    # Accept omission only for the zero-loss control; every non-zero condition
    # must remain visible and equal to the requested value.
    configured=[float(value) for value in re.findall(r'loss(?: random)?\s+([0-9.]+)%',lower)]
    expected=float(loss)
    if expected==0:
        if any(value!=0 for value in configured):raise ValueError('Configured loss mismatch')
    elif not configured or not any(abs(value-expected)<1e-12 for value in configured):
        raise ValueError('Configured loss mismatch')
    if any(name in lower for name in RATE_QDISCS):raise ValueError('Unexpected bandwidth limiter')
def parse_ping(text,sent):
    match=re.search(r'(\d+) packets transmitted, (\d+) received, ([0-9.]+)% packet loss',text)
    if not match:raise ValueError('Missing ping summary')
    tx,rx,loss=int(match.group(1)),int(match.group(2)),float(match.group(3))
    if tx!=sent:raise ValueError('Wrong probe count')
    values=sorted(float(x) for x in re.findall(r'time[=<]([0-9.]+) ms',text))
    if len(values)!=rx or not values:raise ValueError('Incomplete RTT observations')
    return {'probe_packets_sent':tx,'probe_packets_received':rx,'loss_measured_percent':loss,'measured_rtt_min_ms':values[0],'measured_rtt_median_ms':values[len(values)//2] if len(values)%2 else (values[len(values)//2-1]+values[len(values)//2])/2,'measured_rtt_max_ms':values[-1]}
def section(text,start,end):
    match=re.search(re.escape(start)+r'\n(.*?)'+re.escape(end),text,re.S)
    if not match:raise ValueError('Missing section '+start)
    return match.group(1)
def counters(text,prefix):
    block=section(text,f'TCP_{prefix}_BEGIN',f'TCP_{prefix}_END');values={}
    for name in ['TcpRetransSegs','TcpOutSegs','TcpInSegs']:
        match=re.search(r'^'+name+r'\s+(\d+)',block,re.M)
        if not match:raise ValueError('Missing counter '+name)
        values[name]=int(match.group(1))
    return values
def delta(before,after):
    result={k:after[k]-before[k] for k in before}
    if any(v<0 for v in result.values()):raise ValueError('TCP counter reset/wrap')
    return {'tcp_retransmitted_segments':result['TcpRetransSegs'],'tcp_segments_sent':result['TcpOutSegs'],'tcp_segments_received':result['TcpInSegs'],'retransmitted_bytes':None,'scope':'campaign container namespace; not attributable to individual TLS connections'}
def qdisc_drops(text):return sum(int(x) for x in re.findall(r'dropped\s+(\d+)',text))

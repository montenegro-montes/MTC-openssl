"""Extract per-packet and per-scenario summaries with tshark."""
import argparse,csv,hashlib,json,re,subprocess
from pathlib import Path
from decimal import Decimal

FIELDS=['frame.number','frame.time_epoch','frame.len','ip.src','ip.dst','tcp.srcport','tcp.dstport','tcp.len','tcp.analysis.retransmission','tls.record.content_type','tls.handshake.type']
FIELDS += ['ip.len', 'ipv6.src', 'tcp.stream', 'tcp.flags.syn', 'tcp.flags.ack',
           'tcp.seq_raw', 'tcp.ack_raw', 'tcp.analysis.fast_retransmission',
           'tcp.analysis.spurious_retransmission']


def client_random_stream(pcap, client_random, server_port):
    """Ask tshark for ClientHello matches; reuse tcp_stream in the existing extractor."""
    if not isinstance(client_random, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", client_random):
        raise ValueError("missing or malformed native client_random")
    if not isinstance(server_port, int) or not 1 <= server_port <= 65535:
        raise ValueError("invalid server port")
    random_bytes = ":".join(client_random[i:i+2] for i in range(0,64,2)).lower()
    display_filter = (f"tcp.dstport == {server_port} && tls.handshake.type == 1 "
                      f"&& tls.handshake.random == {random_bytes}")
    result = subprocess.run(["tshark", "-2", "-r", str(pcap), "-Y", display_filter,
                             "-T", "fields", "-e", "tcp.stream"],
                            text=True, capture_output=True, check=True, timeout=60)
    values = result.stdout.splitlines()
    if not values:
        raise ValueError("no ClientHello matches native client_random")
    if any(not re.fullmatch(r"[0-9]+", value) for value in values):
        raise ValueError("invalid or ambiguous ClientHello tcp_stream output")
    streams = {int(value) for value in values}
    if len(streams) != 1:
        raise ValueError("multiple streams match native client_random")
    return streams.pop()


def handshake_metrics(rows, server_port, stream=None, allow_incomplete=False):
    """IPv4 capture accounting; fail closed on missing/ambiguous boundaries."""
    def number(r, key):
        value = r.get(key, '')
        if not value or ',' in value:
            raise ValueError('missing or non-scalar ' + key)
        return int(value)

    def flag(r, key):
        return number(r, key) == 1

    candidates = {r['tcp.stream'] for r in rows
                  if str(server_port) in (r['tcp.srcport'], r['tcp.dstport'])}
    if stream is None:
        if len(candidates) != 1:
            raise ValueError('server port must identify exactly one tcp.stream; supply tcp_stream in connections.json')
        stream = next(iter(candidates))
    if str(stream) not in candidates:
        raise ValueError('configured tcp_stream does not match server port')
    flow = sorted((r for r in rows if r['tcp.stream'] == str(stream)),
                  key=lambda r: number(r, 'frame.number'))
    if any(r.get('ipv6.src') or not r.get('ip.src') or not r.get('ip.dst') for r in flow):
        raise ValueError('only single-layer IPv4 flows are supported')
    if len({number(r, 'frame.number') for r in flow}) != len(flow):
        raise ValueError('duplicate frame numbers')
    def partial(reason, syn=None, established=None):
        if not allow_incomplete:
            raise ValueError(reason)
        stamps = [Decimal(r['frame.time_epoch']) for r in flow]
        if any(not t.is_finite() for t in stamps) or stamps != sorted(stamps):
            raise ValueError('non-monotonic or invalid capture timestamps')
        if any(not (number(r,'frame.len') >= number(r,'ip.len') >= number(r,'tcp.len') >= 0) for r in flow):
            raise ValueError('inconsistent frame/IP/TCP lengths')
        endpoints = {frozenset(((r['ip.src'],r['tcp.srcport']),
                               (r['ip.dst'],r['tcp.dstport']))) for r in flow}
        if len(endpoints) != 1:
            raise ValueError('inconsistent stream endpoints')
        def client_tls(kind):
            return [r for r in flow if r['tcp.dstport'] == str(server_port)
                    and kind in r.get('tls.handshake.type','').split(',')]
        hellos, finishes = client_tls('1'), client_tls('20')
        if len(hellos) > 1 or len(finishes) > 1:
            raise ValueError('ambiguous ClientHello/client Finished')
        if finishes:
            raise ValueError('client Finished observed without complete normal boundaries')
        if established and hellos and number(hellos[0],'frame.number') < number(established,'frame.number'):
            raise ValueError('invalid handshake boundary order')
        result = {k:None for k in (
            'tcp_connect_wall_ms','tls_from_pcap_wall_ms','connection_handshake_wall_ms',
            'connection_handshake_packets','connection_handshake_frame_bytes',
            'connection_handshake_ip_bytes','connection_handshake_tcp_payload_bytes',
            'connection_handshake_retransmission_frames')}
        if syn and established:
            result['tcp_connect_wall_ms'] = float((Decimal(established['frame.time_epoch'])-Decimal(syn['frame.time_epoch']))*1000)
        result.update(tcp_stream=int(stream),pcap_analysis_status='PARTIAL',
                      incomplete_reason=reason,tcp_established_observed=established is not None,
                      client_hello_observed=bool(hellos),client_finished_observed=False,
                      last_observed_frame=number(flow[-1],'frame.number'),capture_packet_count=len(flow),
                      capture_retransmission_frames=sum(any(r.get(k) for k in (
                          'tcp.analysis.retransmission','tcp.analysis.fast_retransmission',
                          'tcp.analysis.spurious_retransmission')) for r in flow))
        return result
    syns = [r for r in flow if flag(r, 'tcp.flags.syn') and not flag(r, 'tcp.flags.ack')]
    if not syns:
        return partial('initial SYN missing')
    syn = syns[0]
    if allow_incomplete and number(syn,'tcp.len'):
        raise ValueError('TCP Fast Open is outside this extractor subset')
    client = (syn['ip.src'], syn['tcp.srcport'])
    server = (syn['ip.dst'], syn['tcp.dstport'])
    if server[1] != str(server_port):
        raise ValueError('SYN direction does not match server port')
    def direction(r):
        pair = ((r['ip.src'], r['tcp.srcport']), (r['ip.dst'], r['tcp.dstport']))
        if pair == (client, server): return 'client'
        if pair == (server, client): return 'server'
        raise ValueError('inconsistent stream endpoints')
    for r in flow: direction(r)
    if any(number(r, 'tcp.seq_raw') != number(syn, 'tcp.seq_raw') for r in syns):
        raise ValueError('multiple initial SYN sequence numbers')
    def after(r, start): return number(r, 'frame.number') > number(start, 'frame.number')
    def next_seq(r): return (number(r, 'tcp.seq_raw') + 1) % (1 << 32)
    replies = [r for r in flow if after(r, syn) and direction(r) == 'server'
               and flag(r, 'tcp.flags.syn') and flag(r, 'tcp.flags.ack')
               and number(r, 'tcp.ack_raw') == next_seq(syn)]
    if not replies: return partial('matching SYN-ACK missing',syn)
    syn_ack = replies[0]
    if number(syn, 'tcp.len') or any(number(r, 'tcp.len') for r in replies):
        raise ValueError('TCP Fast Open is outside this extractor subset')
    if any(number(r, 'tcp.seq_raw') != number(syn_ack, 'tcp.seq_raw') for r in replies):
        raise ValueError('ambiguous SYN-ACK sequence numbers')
    acks = [r for r in flow if after(r, syn_ack) and direction(r) == 'client'
            and not flag(r, 'tcp.flags.syn') and flag(r, 'tcp.flags.ack')
            and number(r, 'tcp.seq_raw') == next_seq(syn)
            and number(r, 'tcp.ack_raw') == next_seq(syn_ack)]
    if not acks: return partial('final TCP handshake ACK missing',syn)
    established = acks[0]
    def tls_frames(kind):
        return [r for r in flow if direction(r) == 'client'
                and kind in r.get('tls.handshake.type', '').split(',')]
    hellos, finishes = tls_frames('1'), tls_frames('20')
    if len(hellos) <= 1 and not finishes and allow_incomplete:
        return partial('client Finished unavailable',syn,established)
    if len(hellos) != 1 or len(finishes) != 1:
        raise ValueError('unique ClientHello/client Finished unavailable; check decryption, reassembly or retries')
    hello, finished = hellos[0], finishes[0]
    boundary = [syn, syn_ack, established, hello, finished]
    indices = [number(r, 'frame.number') for r in boundary]
    times = [Decimal(r['frame.time_epoch']) for r in boundary]
    if not (indices[0] < indices[1] < indices[2] <= indices[3] < indices[4]):
        raise ValueError('invalid handshake boundary order')
    interval = [r for r in flow if indices[0] <= number(r, 'frame.number') <= indices[-1]]
    stamps = [Decimal(r['frame.time_epoch']) for r in interval]
    if any(not t.is_finite() for t in stamps):
        raise ValueError('invalid capture timestamps')
    if not (
        times[2] >= times[0] and
        times[4] >= times[3] and
        times[4] >= times[0]
    ):
        raise ValueError('invalid handshake timing boundaries')
    totals = {key: sum(number(r, key) for r in interval)
              for key in ('frame.len', 'ip.len', 'tcp.len')}
    if any(not (number(r,'frame.len') >= number(r,'ip.len') >= number(r,'tcp.len') >= 0) for r in interval):
        raise ValueError('inconsistent frame/IP/TCP lengths')
    result = dict(tcp_stream=int(stream))
    for name, row in zip(('syn','syn_ack','tcp_established','client_hello','client_finished'), boundary):
        result[name + '_frame'] = number(row, 'frame.number')
        result[name + '_time_epoch'] = row['frame.time_epoch']
    result.update(tcp_connect_wall_ms=float((times[2]-times[0])*1000),
                  tls_from_pcap_wall_ms=float((times[4]-times[3])*1000),
                  connection_handshake_wall_ms=float((times[4]-times[0])*1000),
                  connection_handshake_packets=len(interval),
                  connection_handshake_frame_bytes=totals['frame.len'],
                  connection_handshake_ip_bytes=totals['ip.len'],
                  connection_handshake_tcp_payload_bytes=totals['tcp.len'],
                  connection_handshake_retransmission_frames=sum(
                      any(r.get(k) for k in ('tcp.analysis.retransmission',
                          'tcp.analysis.fast_retransmission', 'tcp.analysis.spurious_retransmission'))
                      for r in interval))
    return result


def main():
    parser=argparse.ArgumentParser();parser.add_argument('root',type=Path);parser.add_argument('--allow-incomplete',action='store_true');parser.add_argument('--client-random');args=parser.parse_args();root=args.root.resolve();pcap=root/'handshakes.pcap';keys=root/'tls.keys'
    command=['tshark','-2','-r',str(pcap)]
    if keys.exists() or not args.allow_incomplete: command+=['-o',f'tls.keylog_file:{keys}']
    command+=['-Y','tcp','-T','fields']
    for field in FIELDS:command+=['-e',field]
    command+=['-E','header=y','-E','separator=,','-E','quote=d','-E','occurrence=a']
    result=subprocess.run(command,text=True,capture_output=True,check=True);(root/'tshark.log').write_text(result.stderr);(root/'packets.csv').write_text(result.stdout)
    connections=json.loads((root/'connections.json').read_text());rows=list(csv.DictReader(result.stdout.splitlines()));summary=[]
    for item in connections:
        port=str(item['server_port']);selected=[r for r in rows if r['tcp.srcport']==port or r['tcp.dstport']==port]
        stream = item.get('tcp_stream')
        if args.client_random is not None:
            matched = client_random_stream(pcap, args.client_random, item['server_port'])
            if stream is not None and str(stream) != str(matched):
                raise ValueError('configured tcp_stream conflicts with native client_random')
            stream = matched
        metrics=handshake_metrics(rows, item['server_port'], stream,allow_incomplete=args.allow_incomplete)
        if args.client_random is not None:
            if metrics.get('tcp_stream') != stream:
                raise ValueError('extractor stream association mismatch')
            metrics['client_random'] = args.client_random.lower()
            selected = [r for r in selected if r['tcp.stream'] == str(stream)]
        summary.append({'scenario':item['scenario'],'server_port':item['server_port'],'packets':len(selected),'wire_bytes':sum(int(r['frame.len'] or 0) for r in selected),'tcp_payload_bytes':sum(int(r['tcp.len'] or 0) for r in selected),'retransmission_frames':sum(bool(r['tcp.analysis.retransmission']) for r in selected),'tls_handshake_types':sorted({value for r in selected for value in r['tls.handshake.type'].split(',') if value})})
        summary[-1].update(metrics)
    output={'pcap_sha256':hashlib.sha256(pcap.read_bytes()).hexdigest(),'tls_decryption_keylog_used':keys.exists(), 'allow_incomplete':args.allow_incomplete,'scenarios':summary};(root/'summary.json').write_text(json.dumps(output,indent=2)+'\n');print(root/'summary.json')
if __name__=='__main__':main()

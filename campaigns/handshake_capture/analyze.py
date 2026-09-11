"""Extract per-packet and per-scenario summaries with tshark."""
import argparse,csv,hashlib,json,subprocess
from pathlib import Path

FIELDS=['frame.number','frame.time_epoch','frame.len','ip.src','ip.dst','tcp.srcport','tcp.dstport','tcp.len','tcp.analysis.retransmission','tls.record.content_type','tls.handshake.type']
def main():
    parser=argparse.ArgumentParser();parser.add_argument('root',type=Path);args=parser.parse_args();root=args.root.resolve();pcap=root/'handshakes.pcap';keys=root/'tls.keys'
    command=['tshark','-r',str(pcap),'-o',f'tls.keylog_file:{keys}','-Y','tcp','-T','fields']
    for field in FIELDS:command+=['-e',field]
    command+=['-E','header=y','-E','separator=,','-E','quote=d','-E','occurrence=a']
    result=subprocess.run(command,text=True,capture_output=True,check=True);(root/'tshark.log').write_text(result.stderr);(root/'packets.csv').write_text(result.stdout)
    connections=json.loads((root/'connections.json').read_text());rows=list(csv.DictReader(result.stdout.splitlines()));summary=[]
    for item in connections:
        port=str(item['server_port']);selected=[r for r in rows if r['tcp.srcport']==port or r['tcp.dstport']==port]
        summary.append({'scenario':item['scenario'],'server_port':item['server_port'],'packets':len(selected),'wire_bytes':sum(int(r['frame.len'] or 0) for r in selected),'tcp_payload_bytes':sum(int(r['tcp.len'] or 0) for r in selected),'retransmission_frames':sum(bool(r['tcp.analysis.retransmission']) for r in selected),'tls_handshake_types':sorted({value for r in selected for value in r['tls.handshake.type'].split(',') if value})})
    output={'pcap_sha256':hashlib.sha256(pcap.read_bytes()).hexdigest(),'tls_decryption_keylog_used':True,'scenarios':summary};(root/'summary.json').write_text(json.dumps(output,indent=2)+'\n');print(root/'summary.json')
if __name__=='__main__':main()

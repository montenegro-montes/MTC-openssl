"""Validate capture completeness without treating it as timing evidence."""
import argparse,json,re
from pathlib import Path
def main():
    parser=argparse.ArgumentParser();parser.add_argument('root',type=Path);args=parser.parse_args();root=args.root.resolve();metadata=json.loads((root/'metadata.json').read_text());connections=json.loads((root/'connections.json').read_text());summary=json.loads((root/'summary.json').read_text())
    assert metadata['status']=='captured' and metadata['performance_results'] is False and metadata['source_preserved']
    assert metadata['capture']['interface']=='eth0' and metadata['capture']['bpf_filter']=='tcp portrange 4433-4446'
    assert (root/'handshakes.pcap').stat().st_size>24 and (root/'tls.keys').stat().st_size>0
    assert connections and all(item['passed'] for item in connections)
    assert len(summary['scenarios'])==len(connections) and all(item['packets']>0 and item['wire_bytes']>0 for item in summary['scenarios'])
    log=(root/'tcpdump.log').read_text();drops=re.findall(r'(\d+) packets dropped by kernel',log);assert not drops or all(int(value)==0 for value in drops)
    (root/'validation.json').write_text(json.dumps({'passed':True,'diagnostic_only':True,'scenarios':len(connections),'pcap_sha256':summary['pcap_sha256'],'kernel_drops':sum(map(int,drops)) if drops else 0},indent=2)+'\n');print('validation PASS',root)
if __name__=='__main__':main()

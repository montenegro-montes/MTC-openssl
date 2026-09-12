#!/usr/bin/env python3
"""Manually decode one TLS capture using tshark PDML. Never uses fixtures as payload."""
import argparse
import json
from pathlib import Path
import subprocess
import xml.etree.ElementTree as ET
from validate_mtc import Reader,require,sha,save
import core


def extensions(data):
    r=Reader(data);out={}
    while r.pos<len(data):
        kind=r.number(2);require(kind not in out,'duplicate TLS extension');out[kind]=r.vector()
    r.end();return out

def hello(raw,server=False):
    r=Reader(raw);r.take(2);random=r.take(32);r.vector(1)
    if server:cipher=r.number(2);require(r.number(1)==0,'TLS compression')
    else:r.vector();r.vector(1);cipher=None
    ext=extensions(r.vector());r.end();return ext,cipher,random

def signal(value,expected):
    r=Reader(value);ids=Reader(r.vector());r.end();values=[]
    while ids.pos<len(ids.data):values.append(ids.vector(1))
    ids.end();require(values==[expected],'wrong/ambiguous trust anchor selection')

def extract(a):
    meta=json.loads((a.capture/'metadata.json').read_text())
    require(meta['status']=='CAPTURED_NOT_PROTOCOL_VALIDATED','capture did not complete')
    for name,digest in meta['evidence_sha256'].items():require(sha((a.capture/name).read_bytes())==digest,'endpoint evidence hash mismatch')
    for file,key in [('handshake.pcap','pcap_sha256'),('tls.keys','keylog_sha256')]:
        require(sha((a.capture/file).read_bytes())==meta[key],'capture/keylog integrity mismatch')
    cmd=[a.tshark,'-n','-r',str(a.capture/'handshake.pcap'),'-d','tcp.port==4433,tls',
         '-o','tls.keylog_file:'+str((a.capture/'tls.keys').resolve()),'-o','tcp.desegment_tcp_streams:TRUE',
         '-o','tls.desegment_ssl_records:TRUE','-o','tls.desegment_ssl_application_data:TRUE','-T','pdml']
    result=subprocess.run(cmd,capture_output=True)
    (a.output/'tshark.stderr').write_bytes(result.stderr)
    require(result.returncode==0,'tshark failed; inspect stderr')
    (a.output/'traffic.pdml').write_bytes(result.stdout)
    root=ET.fromstring(result.stdout);messages=[];records=[];streams=set();packets=[];certificates=[]
    sequence=0
    for packet in root.findall('packet'):
        number=packet.find(".//field[@name='frame.number']").get('show')
        stream=packet.find(".//field[@name='tcp.stream']")
        if stream is not None:streams.add(stream.get('show'));packets.append(number)
        for record in packet.findall(".//field[@name='tls.record']"):
            sequence+=1
            length=record.find(".//field[@name='tls.record.length']")
            records.append(dict(record_number=sequence,packet=number,length=length.get('show') if length is not None else None))
        for node in packet.findall(".//field[@name='tls.handshake']"):
            kind=node.find("./field[@name='tls.handshake.type']")
            if kind is None:continue
            # The field's value is the reassembled/decrypted raw handshake, not show text.
            value=node.get('value');require(bool(value),'UNRESOLVED: tshark did not expose raw handshake bytes; retain PDML')
            raw=bytes.fromhex(value);r=Reader(raw);typ=r.number(1);size=r.number(3);body=r.take(size);r.end()
            require(typ==int(kind.get('show')),'tshark/raw message type mismatch')
            row=dict(packet=number,tcp_stream=stream.get('show') if stream is not None else None,type=typ,length=size,total_bytes=len(raw),record_numbers_in_packet=[record['record_number'] for record in records if record['packet']==number])
            messages.append((row,body))
            if typ==11:
                c=Reader(body);require(c.vector(1)==b'','unexpected certificate request context')
                entries=Reader(c.vector(3));c.end();count=0
                while entries.pos<len(entries.data):
                    der=entries.vector(3);ext=extensions(entries.vector());count+=1
                    require(ext.get(0xffa7)==b'','missing/nonempty experimental CertificateEntry confirmation')
                    certificates.append((der,number,ext))
                entries.end();require(count==1,'expected one MTC leaf CertificateEntry')
    require(bool(records),'UNRESOLVED: tshark did not expose TLS record fields')
    require(len(streams)==1,'expected exactly one TCP stream')
    require(len(certificates)==1,'expected exactly one captured certificate; decryption/reassembly may be unavailable')
    def one(typ):
        values=[b for r,b in messages if r['type']==typ];require(len(values)==1,'expected one handshake type '+str(typ));return values[0]
    ch,_,_=hello(one(1));sh,cipher,_=hello(one(2),True)
    require(cipher==0x1302 and sh.get(43)==b'\3\4','wrong cipher/TLS version')
    share=Reader(sh[51]);require(share.number(2)==29,'not X25519');require(len(share.vector())==32,'wrong X25519 key length');share.end()
    require(41 not in ch and 41 not in sh and 42 not in ch,'resumption or early data offered/selected')
    ee=Reader(one(8));ee_ext=extensions(ee.vector());ee.end()
    p=__import__('crypto_profiles').crypto_profile(meta['profile'])
    anchor=core.relid(p['ca_id']+('.1.1.1' if meta['mode']=='landmark' else ''))
    signal(ch[0xffa7],anchor);signal(ee_ext[0xffa7],anchor)
    cv=Reader(one(15));scheme=cv.number(2);signature=cv.vector();cv.end();require(signature,'empty CertificateVerify')
    types=[r['type'] for r,_ in messages]
    require(types.count(20)==2 and 13 not in types and 4 not in types,'expected two Finished, no client auth or tickets')
    require(types.index(1)<types.index(2)<types.index(8)<types.index(11)<types.index(15)<types.index(20),'wrong handshake order')
    der,packet,_=certificates[0]
    with (a.output/'mtc-wire.bin').open('xb') as f:f.write(der)
    outer,_=core.certificate_parts(der);payload_length=len(outer[2][1])-1
    receiver=a.capture/'receiver-reserialized.der'
    receiver_match=None
    if receiver.exists():
        require(sha(receiver.read_bytes())==meta['receiver_reserialized_sha256'],'receiver evidence hash mismatch')
        receiver_match=receiver.read_bytes()==der;require(receiver_match,'receiver reserialization differs from wire')
    client=json.loads((a.capture/'client-result.json').read_text());server=json.loads((a.capture/'server-result.json').read_text())
    require(client['passed'] is True and server['returncode']==0,'endpoint acceptance missing')
    sender_match=sha(der)==meta['fixture_sha256'];require(sender_match,'sender/wire mismatch')
    if a.sender:require(a.sender.read_bytes()==der,'supplied sender fixture differs from capture')
    return dict(overall='PASS',scope='captured TLS framing and endpoint acceptance; run offline object validation next',
        draft=core.DRAFT,claim='implemented-subset conformance',metadata=meta,tcp_stream=next(iter(streams)),
        records=records,handshake_messages=[r for r,_ in messages],certificate_message_length=len(one(11)),
        certificate_verify_length=len(one(15)),certificate_verify_scheme=scheme,mtc_payload_length=payload_length,
        certificate_der_length=len(der),mtc_completion_packets=[packet],tcp_stream_packets=packets,
        fragment_packet_limitation='completion packet is where tshark exposes reassembled data; all stream packet IDs retained in PDML',
        mtc_wire_sha256=sha(der),pcap_sha256=meta['pcap_sha256'],fixture_sha256=meta['fixture_sha256'],
        sender_wire_match=sender_match,receiver_reserialized_wire_match=receiver_match,receiver_raw_sha256=None,
        receiver_limitation='-showcerts reserializes the received X509; original raw input not retained',
        endpoint_authentication=True,tls_version='TLSv1.3',cipher='TLS_AES_256_GCM_SHA384',key_exchange='X25519',
        unresolved=['Private 0xffa7 is not a verified implementation of the complete trust_anchors extension',
                    'CertificateVerify/Finished cryptographic acceptance is endpoint evidence, not independent transcript verification'])

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('capture',type=Path);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--sender',type=Path);p.add_argument('--tshark',default='tshark');a=p.parse_args()
    if a.output.exists():p.error('Extraction output exists; choose a new path')
    a.output.mkdir(parents=True)
    try:report=extract(a)
    except Exception as error:report=dict(overall='UNRESOLVED' if 'UNRESOLVED' in str(error) else 'FAIL',error=str(error))
    save(a.output/'extraction.json',report);print(report['overall'],a.output)
    raise SystemExit(0 if report['overall']=='PASS' else 1)
if __name__=='__main__':main()

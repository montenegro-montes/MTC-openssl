#!/usr/bin/env python3
"""Fail-closed extraction of TCP/TLS handshake metrics from tshark TSV."""
from __future__ import annotations
import argparse,csv,io,json,re,sys
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path

REPO=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(REPO/'src/mtc'))
import core

class AnalysisError(ValueError): pass

BASE_FIELDS=("frame.time_epoch","frame.number","frame.len","tcp.stream","ip.src","ip.dst","ipv6.src","ipv6.dst","tcp.srcport","tcp.dstport","tcp.flags.syn","tcp.flags.ack","tcp.seq","tcp.ack","tcp.len","tcp.payload","tls.handshake.type","tls.handshake.length","tls.handshake.random","tls.record.length","http.request.method","tcp.analysis.retransmission","tcp.analysis.fast_retransmission","tcp.analysis.spurious_retransmission")
STRUCTURED_FIELDS=("tls.handshake.certificate","tls.handshake.certificate_length","tls.handshake.sig_hash_alg","tls.handshake.client_cert_vrfy.sig_len","tls.handshake.client_cert_vrfy.sig")
_STRUCTURED_POSITION=BASE_FIELDS.index("tls.record.length")
# Keep this order identical to the tshark command used by mt-handshake-performance.
FIELDS=(*BASE_FIELDS[:_STRUCTURED_POSITION],*STRUCTURED_FIELDS,*BASE_FIELDS[_STRUCTURED_POSITION:])
METRIC_FIELDS=("tcp_handshake_ms","tcp_syn_to_clienthello_ms","tls_clienthello_to_client_finished_ms","tcp_syn_to_first_application_request_ms","tls_client_handshake_bytes","tls_server_handshake_bytes","tls_handshake_bytes","tls_client_handshake_wire_bytes","tls_server_handshake_wire_bytes","tls_handshake_wire_bytes","tcp_handshake_wire_bytes","connection_handshake_wire_bytes","tls_client_handshake_packets","tls_server_handshake_packets","tls_handshake_packets","tls_client_certificate_bytes","tls_server_certificate_bytes","tls_client_certificate_verify_bytes","tls_server_certificate_verify_bytes","tls_client_certificate_verify_signature_bytes","tls_server_certificate_verify_signature_bytes","tls_client_mtc_proof_bytes","tls_server_mtc_proof_bytes","tls_client_mtc_merkle_path_bytes","tls_server_mtc_merkle_path_bytes","tls_client_mtc_merkle_path_hashes","tls_server_mtc_merkle_path_hashes","tls_client_sct_bytes","tls_server_sct_bytes","tls_client_authentication_bytes","tls_server_authentication_bytes","tls_authentication_bytes","authentication_components_status","authentication_components_error","tcp_stream","client_random","analysis_status","analysis_error","tcp_retransmission_packets")

def _items(value): return [x.strip() for x in value.split(',') if x.strip()]
def _yes(value): return value.strip().lower() in {'1','true'}
def _integer(row,key):
 try:return int(row[key])
 except (KeyError,TypeError,ValueError) as e:raise AnalysisError(f"frame {row.get('frame.number','?')}: invalid {key}") from e
def _time(row):
 try:return Decimal(row['frame.time_epoch'])
 except (KeyError,TypeError,ValueError) as e:raise AnalysisError(f"frame {row.get('frame.number','?')}: invalid timestamp") from e
def _address(row,prefix):
 value=row.get(f'ip.{prefix}','') or row.get(f'ipv6.{prefix}','')
 if not value:raise AnalysisError(f"frame {row.get('frame.number','?')}: {prefix} address missing")
 return value
@dataclass(frozen=True)
class Endpoint: address:str;port:str
def _source(row):return Endpoint(_address(row,'src'),row.get('tcp.srcport',''))
def _destination(row):return Endpoint(_address(row,'dst'),row.get('tcp.dstport',''))
def _retransmission(row):return any(_yes(row.get(k,'')) for k in BASE_FIELDS[-3:])

def load_tsv(path):
 with path.open(newline='') as source:lines=list(csv.reader(source,delimiter='\t'))
 rows=[]
 for line,values in enumerate(lines,1):
  if len(values) not in (len(BASE_FIELDS),len(FIELDS)):raise AnalysisError(f'TSV line {line}: expected {len(BASE_FIELDS)} or {len(FIELDS)} fields, got {len(values)}')
  if len(values)==len(BASE_FIELDS):
   row=dict(zip(BASE_FIELDS,values));row.update(dict.fromkeys(STRUCTURED_FIELDS,''))
  else:row=dict(zip(FIELDS,values))
  rows.append(row)
 return rows

def _one_value(row,key,required=False):
 values=_items(row.get(key,''))
 if required and len(values)!=1:raise AnalysisError(f"frame {row.get('frame.number','?')}: expected one {key}")
 if len(values)>1:raise AnalysisError(f"frame {row.get('frame.number','?')}: ambiguous {key}")
 return values[0] if values else None

def _certificate_verify(row,body_length):
 algorithms=_items(row.get('tls.handshake.sig_hash_alg',''))
 length=_one_value(row,'tls.handshake.client_cert_vrfy.sig_len',True)
 encoded=_one_value(row,'tls.handshake.client_cert_vrfy.sig',True)
 try:
  if not algorithms:raise ValueError('missing signature algorithm')
  for algorithm in algorithms:int(algorithm,0)
  signature_length=int(length,0);signature=bytes.fromhex(encoded.replace(':',''))
 except ValueError as e:raise AnalysisError(f"frame {row.get('frame.number','?')}: malformed CertificateVerify") from e
 if not signature or len(signature)!=signature_length:raise AnalysisError(f"frame {row.get('frame.number','?')}: CertificateVerify signature length mismatch")
 if body_length!=2+2+signature_length:raise AnalysisError(f"frame {row.get('frame.number','?')}: invalid TLS 1.3 CertificateVerify structure")
 return body_length+4,signature_length

def _mtc_components(der,mode):
 try:
  outer,_=core.certificate_parts(der);bits=outer[2][1]
  if not bits or bits[0]!=0:raise ValueError('non-octet-aligned MTCProof')
  proof=bits[1:];components=core.proof_components(proof)
  if mode=='landmark' and components['signatures']:raise ValueError('landmark MTCProof contains signatures')
  if mode=='standalone' and not components['signatures']:raise ValueError('standalone MTCProof lacks signatures')
 except (ValueError,IndexError) as e:raise AnalysisError('malformed MTC credential: '+str(e)) from e
 path=components['inclusion_proof']
 return len(proof),len(path),len(path)//32

def _sct_size(der):
 """Return exact SCT-list extnValue bytes, or zero when the extension is absent."""
 try:
  _,tbs=core.certificate_parts(der);extensions=next((item for item in tbs if item[0]==0xa3),None)
  if extensions is None:return 0
  values=core.items(core.content(extensions[1],0x30));target=core.oid('1.3.6.1.4.1.11129.2.4.2')
  found=[]
  for extension in values:
   parts=core.items(core.content(extension[2],0x30))
   if parts and parts[0][2]==target:
    if parts[-1][0]!=4:raise ValueError('SCT extnValue is not an OCTET STRING')
    found.append(len(parts[-1][1]))
  if len(found)>1:raise ValueError('duplicate SCT extension')
  return found[0] if found else 0
 except (ValueError,IndexError) as e:raise AnalysisError('malformed certificate SCT extension: '+str(e)) from e

def _handshakes(row):
 kinds,lengths=_items(row.get('tls.handshake.type','')),_items(row.get('tls.handshake.length',''))
 if len(kinds)!=len(lengths):
  label='Certificate length unavailable' if '11' in kinds else 'handshake message length unavailable'
  raise AnalysisError(f"frame {row.get('frame.number','?')}: {label}")
 try:return list(zip(kinds,map(int,lengths)))
 except ValueError as e:raise AnalysisError(f"frame {row.get('frame.number','?')}: invalid handshake length") from e

def _logical_records(rows):
 octets={}
 for row in rows:
  raw=row.get('tcp.payload','').replace(':','')
  try:data=bytes.fromhex(raw)
  except ValueError as e:raise AnalysisError(f"frame {row.get('frame.number','?')}: invalid tcp.payload") from e
  if len(data)!=_integer(row,'tcp.len'):raise AnalysisError(f"frame {row.get('frame.number','?')}: tcp.payload length mismatch")
  start=_integer(row,'tcp.seq')
  for offset,value in enumerate(data):
   position=start+offset
   if position in octets and octets[position]!=value:raise AnalysisError(f"frame {row.get('frame.number','?')}: conflicting retransmitted TCP payload")
   octets[position]=value
 if not octets:raise AnalysisError('TLS TCP payload unavailable for measured direction')
 positions=sorted(octets)
 if positions!=list(range(positions[0],positions[-1]+1)):raise AnalysisError('gap in reassembled TLS TCP payload')
 data=bytes(octets[position] for position in positions);offset=0
 while offset<len(data):
  if len(data)-offset<5:raise AnalysisError('truncated TLS record header in reassembled TCP payload')
  if data[offset] not in (20,21,22,23):raise AnalysisError('invalid TLS record content type in reassembled TCP payload')
  length=int.from_bytes(data[offset+3:offset+5],'big');end=offset+5+length
  if end>len(data):raise AnalysisError('fragmented TLS record is incomplete at handshake boundary')
  offset=end
 return len(data)

def analyze(rows,server_port='4433',expect_client_certificate=False,credential_kind='auto'):
 syns=[r for r in rows if r.get('tcp.dstport')==server_port and _yes(r.get('tcp.flags.syn','')) and not _yes(r.get('tcp.flags.ack',''))]
 streams={r.get('tcp.stream','') for r in syns}
 if len(syns)!=1 or len(streams)!=1 or '' in streams:raise AnalysisError(f'expected one initial SYN/flow, found {len(syns)} SYNs in {len(streams)} streams')
 syn=syns[0];stream=syn['tcp.stream'];flow=[r for r in rows if r.get('tcp.stream')==stream];client,server=_source(syn),_destination(syn)
 def c2s(r):return _source(r)==client and _destination(r)==server
 def s2c(r):return _source(r)==server and _destination(r)==client
 def direction(r):
  if c2s(r):return 'client'
  if s2c(r):return 'server'
  raise AnalysisError(f"frame {r.get('frame.number','?')}: unknown direction")
 syn_time=_time(syn);syn_seq=_integer(syn,'tcp.seq')
 synacks=[r for r in flow if s2c(r) and _yes(r.get('tcp.flags.syn','')) and _yes(r.get('tcp.flags.ack','')) and _time(r)>=syn_time and _integer(r,'tcp.ack')==syn_seq+1]
 if len(synacks)!=1:raise AnalysisError(f'expected one corresponding SYN/ACK, found {len(synacks)}')
 synack=synacks[0];synack_time=_time(synack);synack_seq=_integer(synack,'tcp.seq')
 hellos=[r for r in flow if c2s(r) and '1' in _items(r.get('tls.handshake.type','')) and _time(r)>=synack_time]
 if len(hellos)!=1:raise AnalysisError(f'expected one client ClientHello, found {len(hellos)}')
 hello=hellos[0];hello_time=_time(hello);randoms=_items(hello.get('tls.handshake.random',''))
 client_random=randoms[0].replace(':','').lower() if len(randoms)==1 else ''
 if not re.fullmatch(r'[0-9a-f]{64}',client_random):raise AnalysisError('ClientHello client_random missing, malformed, or ambiguous')
 acks=[r for r in flow if c2s(r) and not _yes(r.get('tcp.flags.syn','')) and _yes(r.get('tcp.flags.ack','')) and synack_time<=_time(r)<=hello_time and _integer(r,'tcp.ack')==synack_seq+1]
 if not acks:raise AnalysisError('expected ACK completing the TCP handshake, found 0')
 ack_time=min(_time(r) for r in acks);first_acks=[r for r in acks if _time(r)==ack_time]
 if len(first_acks)!=1:raise AnalysisError(f'ACK completing the TCP handshake is ambiguous: {len(first_acks)} frames at the first ACK time')
 ack=first_acks[0]
 finishes=[r for r in flow if c2s(r) and '20' in _items(r.get('tls.handshake.type','')) and _time(r)>=hello_time]
 if len(finishes)!=1:raise AnalysisError(f'expected one client Finished, found {len(finishes)}')
 finished=finishes[0];finished_time=_time(finished)
 requests=[r for r in flow if c2s(r) and _items(r.get('http.request.method','')) and _time(r)>=finished_time]
 request_time=None
 if requests:
  request_time=min(_time(r) for r in requests);first_requests=[r for r in requests if _time(r)==request_time]
  if len(first_requests)!=1:raise AnalysisError('first HTTP request is ambiguous')
  if first_requests[0] is finished:raise AnalysisError('application request shares the client Finished frame; TLS boundary is ambiguous')
 if not(syn_time<=synack_time<=_time(ack)<=hello_time<=finished_time):raise AnalysisError('required TCP/TLS events are not in logical order')
 if request_time is not None and finished_time>request_time:raise AnalysisError('HTTP request precedes client Finished')
 interval=[r for r in flow if hello_time<=_time(r)<=finished_time and _integer(r,'tcp.len')>0]
 client_frames=[r for r in interval if c2s(r)];server_frames=[r for r in interval if s2c(r)]
 if len(client_frames)+len(server_frames)!=len(interval):raise AnalysisError('TLS interval contains a frame with an unknown direction')
 client_wire=sum(_integer(r,'frame.len') for r in client_frames);server_wire=sum(_integer(r,'frame.len') for r in server_frames)
 tcp_frames=(syn,synack,ack);tcp_wire=sum(_integer(r,'frame.len') for r in tcp_frames)
 connection_frames={_integer(r,'frame.number'):r for r in (*tcp_frames,*interval)}
 connection_wire=sum(_integer(r,'frame.len') for r in connection_frames.values())
 client_tls=_logical_records(client_frames);server_tls=_logical_records(server_frames)
 certs={'client':set(),'server':set()};cert_der={'client':[],'server':[]};cert_der_error={'client':None,'server':None};certificate_verifies={'client':[],'server':[]};certificate_request=False
 for row in interval:
  for kind,length in _handshakes(row):
   certificate_request|=kind=='13'
   side=direction(row)
   if kind=='11':
    certs[side].add(length+4)
    encoded_items=_items(row.get('tls.handshake.certificate',''))
    declared_items=_items(row.get('tls.handshake.certificate_length',''))
    try:
     decoded=[bytes.fromhex(encoded.replace(':','')) for encoded in encoded_items]
     if declared_items:
      declared=[int(value,0) for value in declared_items]
      if len(declared)!=len(decoded) or any(size!=len(value) for size,value in zip(declared,decoded)):
       raise ValueError('CertificateEntry length mismatch')
     cert_der[side].extend(decoded)
    except ValueError as e:
     cert_der[side].clear();cert_der_error[side]=f"frame {row.get('frame.number','?')}: CertificateEntry DER unavailable: {e}"
   if kind=='15':certificate_verifies[side].append(_certificate_verify(row,length))
 if len(certs['server'])!=1:raise AnalysisError(f"expected one analyzable server Certificate, found {len(certs['server'])}")
 if len(certs['client'])>1:raise AnalysisError(f"expected at most one analyzable client Certificate, found {len(certs['client'])}")
 if (certificate_request or expect_client_certificate) and not certs['client']:raise AnalysisError('client Certificate was required/requested but is not analyzable')
 if len(certificate_verifies['server'])!=1:raise AnalysisError(f"expected one server CertificateVerify, found {len(certificate_verifies['server'])}")
 if len(certificate_verifies['client'])>1:raise AnalysisError(f"expected at most one client CertificateVerify, found {len(certificate_verifies['client'])}")
 if (certificate_request or expect_client_certificate) and len(certificate_verifies['client'])!=1:raise AnalysisError('client CertificateVerify was required/requested but is not analyzable')
 client_cert=next(iter(certs['client'])) if certs['client'] else 0;server_cert=next(iter(certs['server']))
 client_cv,client_sig=certificate_verifies['client'][0] if certificate_verifies['client'] else (0,0)
 server_cv,server_sig=certificate_verifies['server'][0]
 mtc={side:(None,None,None) for side in ('client','server')}
 component_errors=[]
 if credential_kind.startswith('mtc-'):
  for side in ('client','server'):
   if certs[side]:
    if cert_der_error[side]:component_errors.append(cert_der_error[side])
    elif len(cert_der[side])>1:raise AnalysisError(f'expected one {side} MTC CertificateEntry DER value')
    elif cert_der[side]:mtc[side]=_mtc_components(cert_der[side][0],credential_kind.removeprefix('mtc-'))
    else:component_errors.append(f'{side} MTC CertificateEntry DER unavailable from tshark')
 sct={side:None for side in ('client','server')}
 if credential_kind=='x509':
  for side in ('client','server'):
   if cert_der_error[side]:component_errors.append(cert_der_error[side]+'; SCT size unavailable')
   elif cert_der[side]:sct[side]=sum(_sct_size(cert) for cert in cert_der[side])
   elif certs[side]:component_errors.append(f'{side} X.509 CertificateEntry DER unavailable from tshark; SCT size unavailable')
 ms=Decimal(1000)
 return {'tcp_handshake_ms':float((_time(ack)-syn_time)*ms),'tcp_syn_to_clienthello_ms':float((hello_time-syn_time)*ms),'tls_clienthello_to_client_finished_ms':float((finished_time-hello_time)*ms),'tcp_syn_to_first_application_request_ms':None if request_time is None else float((request_time-syn_time)*ms),'tls_client_handshake_bytes':client_tls,'tls_server_handshake_bytes':server_tls,'tls_handshake_bytes':client_tls+server_tls,'tls_client_handshake_wire_bytes':client_wire,'tls_server_handshake_wire_bytes':server_wire,'tls_handshake_wire_bytes':client_wire+server_wire,'tcp_handshake_wire_bytes':tcp_wire,'connection_handshake_wire_bytes':connection_wire,'tls_client_handshake_packets':len(client_frames),'tls_server_handshake_packets':len(server_frames),'tls_handshake_packets':len(interval),'tls_client_certificate_bytes':client_cert,'tls_server_certificate_bytes':server_cert,'tls_client_certificate_verify_bytes':client_cv,'tls_server_certificate_verify_bytes':server_cv,'tls_client_certificate_verify_signature_bytes':client_sig,'tls_server_certificate_verify_signature_bytes':server_sig,'tls_client_mtc_proof_bytes':mtc['client'][0],'tls_server_mtc_proof_bytes':mtc['server'][0],'tls_client_mtc_merkle_path_bytes':mtc['client'][1],'tls_server_mtc_merkle_path_bytes':mtc['server'][1],'tls_client_mtc_merkle_path_hashes':mtc['client'][2],'tls_server_mtc_merkle_path_hashes':mtc['server'][2],'tls_client_sct_bytes':sct['client'],'tls_server_sct_bytes':sct['server'],'tls_client_authentication_bytes':client_cert+client_cv,'tls_server_authentication_bytes':server_cert+server_cv,'tls_authentication_bytes':client_cert+client_cv+server_cert+server_cv,'authentication_components_status':'UNAVAILABLE' if component_errors else 'OK','authentication_components_error':'; '.join(component_errors),'tcp_stream':int(stream),'client_random':client_random,'analysis_status':'OK','analysis_error':'','tcp_retransmission_packets':sum(_retransmission(r) for r in interval)}

def analyze_safe(rows,server_port='4433',expect_client_certificate=False,credential_kind='auto'):
 try:return analyze(rows,server_port,expect_client_certificate,credential_kind)
 except AnalysisError as e:
  result={f:None for f in METRIC_FIELDS};streams={r.get('tcp.stream','') for r in rows if r.get('tcp.stream','')}
  stream=next(iter(streams)) if len(streams)==1 else ''
  randoms={value.replace(':','').lower() for r in rows if '1' in _items(r.get('tls.handshake.type','')) for value in _items(r.get('tls.handshake.random',''))}
  client_random=next(iter(randoms)) if len(randoms)==1 and re.fullmatch(r'[0-9a-f]{64}',next(iter(randoms))) else None
  result.update(tcp_stream=int(stream) if stream.isdigit() else None,client_random=client_random,analysis_status='ERROR',analysis_error=str(e))
  return result

def main():
 p=argparse.ArgumentParser();p.add_argument('tsv',type=Path);p.add_argument('--server-port',default='4433');p.add_argument('--expect-client-certificate',action='store_true');p.add_argument('--credential-kind',choices=('auto','x509','mtc-landmark','mtc-standalone'),default='auto');p.add_argument('--format',choices=('json','tsv','csv'),default='json');a=p.parse_args()
 try:result=analyze_safe(load_tsv(a.tsv),a.server_port,a.expect_client_certificate,a.credential_kind)
 except AnalysisError as e:result={f:None for f in METRIC_FIELDS};result.update(analysis_status='ERROR',analysis_error=str(e))
 values=[result[f] for f in METRIC_FIELDS]
 if a.format=='tsv':print('\t'.join('' if v is None else str(v) for v in values))
 elif a.format=='csv':
  out=io.StringIO();csv.writer(out,lineterminator='').writerow(values);print(out.getvalue())
 else:print(json.dumps(result,separators=(',',':')))
 return 0 if result['analysis_status']=='OK' else 2
if __name__=='__main__':raise SystemExit(main())

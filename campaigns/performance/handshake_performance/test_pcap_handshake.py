#!/usr/bin/env python3
from pathlib import Path
import sys,unittest
sys.path.insert(0,str(Path(__file__).parent))
import pcap_handshake as p

RANDOM='ab'*32
def record(length,marker):return (bytes((23,3,3))+length.to_bytes(2,'big')+bytes((marker,))*length).hex()
def row(number,time,src,dst,sport,dport,**kw):
 values={field:'' for field in p.FIELDS};values.update({'frame.time_epoch':str(time),'frame.number':str(number),'frame.len':'66','tcp.stream':'0','ip.src':src,'ip.dst':dst,'tcp.srcport':str(sport),'tcp.dstport':str(dport),'tcp.flags.syn':'False','tcp.flags.ack':'True','tcp.seq':'1','tcp.ack':'1','tcp.len':'0','tcp.analysis.retransmission':'False','tcp.analysis.fast_retransmission':'False','tcp.analysis.spurious_retransmission':'False'});values.update({k.replace('_','.'):str(v) for k,v in kw.items()});return values

def fixture(mutual=False,fragment=False,retransmission=False):
 c,s='10.0.0.2','10.0.0.3';rows=[
 row(1,'0',c,s,50000,4433,**{'tcp_flags_syn':'True','tcp_flags_ack':'False','tcp_seq':'0','tcp_ack':'0'}),
 row(2,'.000024',s,c,4433,50000,**{'tcp_flags_syn':'True','tcp_seq':'0','tcp_ack':'1'}),
 row(3,'.000045',c,s,50000,4433),
 row(4,'.000957',c,s,50000,4433,**{'frame_len':'414','tcp_seq':'1','tcp_len':'109','tcp_payload':record(104,1),'tls_handshake_type':'1','tls_handshake_length':'100','tls_handshake_random':RANDOM,'tls_record_length':'104'}),
 ]
 server_types='2,8,13,11,15,20' if mutual else '2,8,11,15,20';server_lengths='50,20,8,300,60,32' if mutual else '50,20,300,60,32';record_lengths=[54,24,12,304,64,36] if mutual else [54,24,304,64,36];server_payload=''.join(record(n,i+10) for i,n in enumerate(record_lengths));server_size=len(bytes.fromhex(server_payload))
 if fragment:
  split=200;rows.append(row(5,'.002',s,c,4433,50000,**{'frame_len':'500','tcp_seq':'1','tcp_len':str(split),'tcp_payload':server_payload[:split*2]}));server_seq=1+split;payload=server_payload[split*2:]
 else:server_seq=1;payload=server_payload
 rows.append(row(6,'.003805',s,c,4433,50000,**{'frame_len':'893','tcp_seq':str(server_seq),'tcp_len':str(len(bytes.fromhex(payload))),'tcp_payload':payload,'tls_handshake_type':server_types,'tls_handshake_length':server_lengths,'tls_record_length':','.join(map(str,record_lengths))}))
 rows[-1].update({'tls.handshake.sig_hash_alg':'0x0403','tls.handshake.client_cert_vrfy.sig_len':'56','tls.handshake.client_cert_vrfy.sig':'aa'*56})
 if mutual:
  rows.append(row(7,'.006',c,s,50000,4433,**{'frame_len':'250','tcp_seq':'110','tcp_len':'149','tcp_payload':record(144,30),'tls_handshake_type':'11','tls_handshake_length':'140','tls_record_length':'144'}));finished_seq=259
  rows.append(row(75,'.007',c,s,50000,4433,**{'frame_len':'114','tcp_seq':'259','tcp_len':'49','tcp_payload':record(44,32),'tls_handshake_type':'15','tls_handshake_length':'44','tls_record_length':'44'}));rows[-1].update({'tls.handshake.sig_hash_alg':'0x0403','tls.handshake.client_cert_vrfy.sig_len':'40','tls.handshake.client_cert_vrfy.sig':'bb'*40});finished_seq=308
 else:finished_seq=110
 rows.append(row(8,'.008212',c,s,50000,4433,**{'frame_len':'146','tcp_seq':str(finished_seq),'tcp_len':'41','tcp_payload':record(36,31),'tls_handshake_type':'20','tls_handshake_length':'32','tls_record_length':'36'}))
 if retransmission:
  rows.insert(-1,row(70,'.007',s,c,4433,50000,**{'frame_len':'893','tcp_seq':'1','tcp_len':str(server_size),'tcp_payload':server_payload,'tls_record_length':','.join(map(str,record_lengths)),'tcp_analysis_retransmission':'True'}))
 rows.extend([row(9,'.009',c,s,50000,4433,**{'frame_len':'106','tcp_len':'40','http_request_method':'GET'}),row(10,'.010',s,c,4433,50000,**{'frame_len':'90','tcp_len':'24'}),row(11,'.011',c,s,50000,4433)])
 return rows

class Tests(unittest.TestCase):
 def test_complete_schema_and_boundaries(self):
  r=p.analyze(fixture())
  self.assertAlmostEqual(r['tcp_handshake_ms'],.045);self.assertAlmostEqual(r['tcp_syn_to_clienthello_ms'],.957);self.assertAlmostEqual(r['tls_clienthello_to_client_finished_ms'],7.255);self.assertAlmostEqual(r['tcp_syn_to_first_application_request_ms'],9)
  self.assertEqual(r['tls_client_handshake_bytes'],150);self.assertEqual(r['tls_server_handshake_bytes'],507);self.assertEqual(r['tls_handshake_bytes'],657)
  self.assertEqual((r['tls_client_handshake_wire_bytes'],r['tls_server_handshake_wire_bytes'],r['tls_handshake_wire_bytes']),(560,893,1453))
  self.assertEqual((r['tcp_handshake_wire_bytes'],r['connection_handshake_wire_bytes']),(198,1651))
  self.assertEqual((r['tls_client_handshake_packets'],r['tls_server_handshake_packets'],r['tls_handshake_packets']),(2,1,3));self.assertEqual(r['tls_client_certificate_bytes'],0);self.assertEqual(r['tls_server_certificate_bytes'],304);self.assertEqual((r['tcp_stream'],r['client_random'],r['analysis_status']),(0,RANDOM,'OK'))
  self.assertEqual((r['tls_server_certificate_verify_bytes'],r['tls_server_certificate_verify_signature_bytes']),(64,56))
  self.assertEqual((r['tls_client_certificate_verify_bytes'],r['tls_client_certificate_verify_signature_bytes']),(0,0))
  self.assertEqual((r['tls_server_authentication_bytes'],r['tls_authentication_bytes']),(368,368))
 def test_valid_handshake_without_http_keeps_tls_metrics(self):
  with_http=p.analyze(fixture());without_http=p.analyze([row for row in fixture() if not row['http.request.method']])
  self.assertIsNone(without_http['tcp_syn_to_first_application_request_ms'])
  for metric in p.METRIC_FIELDS:
   if metric!='tcp_syn_to_first_application_request_ms':self.assertEqual(without_http[metric],with_http[metric])
 def test_multiple_records_include_each_header(self):
  self.assertEqual(p.analyze(fixture())['tls_server_handshake_bytes'],sum((54,24,304,64,36))+5*5)
 def test_fragmented_record_is_counted_once_but_both_wire_frames_count(self):
  r=p.analyze(fixture(fragment=True));self.assertEqual(r['tls_server_handshake_bytes'],507);self.assertEqual(r['tls_server_handshake_packets'],2);self.assertEqual(r['tls_server_handshake_wire_bytes'],1393)
 def test_retransmission_is_wire_cost_not_duplicate_logical_bytes(self):
  r=p.analyze(fixture(retransmission=True));self.assertEqual(r['tls_server_handshake_bytes'],507);self.assertEqual(r['tls_server_handshake_wire_bytes'],1786);self.assertEqual(r['tls_server_handshake_packets'],2);self.assertEqual(r['tcp_retransmission_packets'],1)
 def test_ack_with_clienthello_is_counted_once_in_connection_wire_bytes(self):
  rows=[r for r in fixture() if r['frame.number']!='3'];r=p.analyze(rows)
  self.assertEqual(r['tcp_handshake_wire_bytes'],546);self.assertEqual(r['tls_handshake_wire_bytes'],1453)
  self.assertEqual(r['connection_handshake_wire_bytes'],1585)
 def test_mutual_client_certificate(self):
  r=p.analyze(fixture(mutual=True));self.assertEqual(r['tls_client_certificate_bytes'],144);self.assertEqual(r['tls_server_certificate_bytes'],304)
  self.assertEqual((r['tls_client_certificate_verify_bytes'],r['tls_client_certificate_verify_signature_bytes']),(48,40))
  self.assertEqual(r['tls_authentication_bytes'],144+48+304+64)
 def test_requested_client_certificate_unavailable_is_error_not_zero(self):
  rows=fixture(mutual=True);rows=[r for r in rows if r['frame.number'] not in ('7','75')];next(r for r in rows if r['frame.number']=='8')['tcp.seq']='110';r=p.analyze_safe(rows,expect_client_certificate=True);self.assertEqual(r['analysis_status'],'ERROR');self.assertIsNone(r['tls_client_certificate_bytes']);self.assertEqual(r['client_random'],RANDOM);self.assertIn('not analyzable',r['analysis_error'])
 def test_present_certificate_without_length_is_error(self):
  rows=fixture();rows[4]['tls.handshake.length']='';r=p.analyze_safe(rows);self.assertEqual(r['analysis_status'],'ERROR');self.assertIsNone(r['tls_server_certificate_bytes'])
 def test_malformed_certificate_verify_is_rejected(self):
  rows=fixture();rows[4]['tls.handshake.client_cert_vrfy.sig_len']='55'
  r=p.analyze_safe(rows);self.assertEqual(r['analysis_status'],'ERROR');self.assertIn('signature length mismatch',r['analysis_error'])
 def test_missing_required_certificate_verify_is_rejected(self):
  rows=fixture();server=next(row for row in rows if row['frame.number']=='6')
  server['tls.handshake.type']='2,8,11,20';server['tls.handshake.length']='1206,2,436,48'
  result=p.analyze_safe(rows);self.assertEqual(result['analysis_status'],'ERROR');self.assertIn('server CertificateVerify',result['analysis_error'])
 def test_missing_clienthello_is_rejected(self):
  result=p.analyze_safe([row for row in fixture() if row['frame.number']!='4'])
  self.assertEqual(result['analysis_status'],'ERROR');self.assertIn('client ClientHello',result['analysis_error'])
 def test_mtc_landmark_and_standalone_proof_components(self):
  validity=p.core.seq(p.core.der(24,b'20200101000000Z'),p.core.der(24,b'20990101000000Z'))
  tbs=p.core.seq(p.core.der(0xa0,p.core.integer(2)),p.core.integer(1<<48),p.core.ALG,p.core.name('32473.101'),validity,p.core.seq(),p.core.seq())
  for mode,signatures in (('landmark',()),('standalone',(('32473.101',b'signature'),))):
   proof=p.core.proof(0,16,(b'a'*32,b'b'*32),signatures)
   der=p.core.certificate(tbs,proof);rows=fixture();rows[4]['tls.handshake.certificate']=der.hex();rows[4]['tls.handshake.certificate_length']=str(len(der))
   result=p.analyze(rows,credential_kind='mtc-'+mode)
   self.assertEqual(result['tls_server_mtc_proof_bytes'],len(proof));self.assertEqual(result['tls_server_mtc_merkle_path_bytes'],64);self.assertEqual(result['tls_server_mtc_merkle_path_hashes'],2)
   self.assertIsNone(result['tls_client_mtc_proof_bytes'])
 def test_mtc_mutual_parses_both_proofs(self):
  validity=p.core.seq(p.core.der(24,b'20200101000000Z'),p.core.der(24,b'20990101000000Z'))
  tbs=p.core.seq(p.core.der(0xa0,p.core.integer(2)),p.core.integer(1<<48),p.core.ALG,p.core.name('32473.101'),validity,p.core.seq(),p.core.seq())
  proof=p.core.proof(0,16,(b'a'*32,),(('32473.101',b'signature'),));der=p.core.certificate(tbs,proof)
  rows=fixture(mutual=True)
  for number in ('6','7'):
   target=next(row for row in rows if row['frame.number']==number);target['tls.handshake.certificate']=der.hex();target['tls.handshake.certificate_length']=str(len(der))
  result=p.analyze(rows,expect_client_certificate=True,credential_kind='mtc-standalone')
  self.assertEqual(result['tls_server_mtc_merkle_path_hashes'],1);self.assertEqual(result['tls_client_mtc_merkle_path_hashes'],1)
 def test_mtc_mode_mismatch_is_rejected(self):
  validity=p.core.seq(p.core.der(24,b'20200101000000Z'),p.core.der(24,b'20990101000000Z'))
  tbs=p.core.seq(p.core.der(0xa0,p.core.integer(2)),p.core.integer(1<<48),p.core.ALG,p.core.name('32473.101'),validity,p.core.seq(),p.core.seq())
  der=p.core.certificate(tbs,p.core.proof(0,16,(b'a'*32,),()))
  rows=fixture();rows[4]['tls.handshake.certificate']=der.hex()
  result=p.analyze_safe(rows,credential_kind='mtc-standalone')
  self.assertEqual(result['analysis_status'],'ERROR');self.assertIn('lacks signatures',result['analysis_error'])
 def test_sct_extension_size_and_absence(self):
  validity=p.core.seq(p.core.der(24,b'20200101000000Z'),p.core.der(24,b'20990101000000Z'))
  base=(p.core.der(0xa0,p.core.integer(2)),p.core.integer(1),p.core.ALG,p.core.name('32473.101'),validity,p.core.seq(),p.core.seq())
  plain=p.core.certificate(p.core.seq(*base),b'proof')
  sct=b'\x00\x03abc';extension=p.core.seq(p.core.oid('1.3.6.1.4.1.11129.2.4.2'),p.core.der(4,sct))
  with_sct=p.core.certificate(p.core.seq(*base,p.core.der(0xa3,p.core.seq(extension))),b'proof')
  self.assertEqual(p._sct_size(plain),0);self.assertEqual(p._sct_size(with_sct),len(sct))
 def test_post_handshake_http_and_close_are_not_handshake_cost(self):
  full=p.analyze(fixture());trim=p.analyze(fixture()[:7]+[fixture()[8]])
  for key in ('tls_handshake_bytes','tls_handshake_wire_bytes','tls_handshake_packets'):self.assertEqual(full[key],trim[key])
 def test_missing_event_and_ambiguous_flow_are_controlled_errors(self):
  rows=[r for r in fixture() if r['frame.number']!='3'];rows[2]['tcp.ack']='0';self.assertEqual(p.analyze_safe(rows)['analysis_status'],'ERROR')
  rows=fixture();rows.append(row(20,'.1','10.0.0.4','10.0.0.3',50001,4433,**{'tcp_stream':'1','tcp_flags_syn':'True','tcp_flags_ack':'False','tcp_seq':'0','tcp_ack':'0'}));self.assertIn('one initial SYN/flow',p.analyze_safe(rows)['analysis_error'])
 def test_header_preserves_identity_and_has_no_obsolete_names(self):
  text=(Path(__file__).resolve().parents[3]/'bin/performance/mt-handshake-performance').read_text();header='profile,case,key_establishment,openssl_group,phase,repetition,'+','.join(p.METRIC_FIELDS);self.assertIn("printf '"+header+"\\n'",text)
  self.assertIn('for phase in warmup measured; do',text)
  self.assertIn('(WARMUPS + RUNS)',text)
  self.assertIn('${profile}-${case_name}-${phase}-${repetition}',text)
  for obsolete in ('connection_syn_to_clienthello_ms','connection_syn_to_client_finished_ms','tls_handshake_frame_count,'):self.assertNotIn(obsolete,text)
if __name__=='__main__':unittest.main()

"""Deterministic offline tests; no capture, network, Docker or tshark required."""
import copy
import unittest
from analyze import FIELDS, handshake_metrics


def fixture():
    rows = []
    # SYN, SYN-ACK, ACK+ClientHello, server handshake, client Finished, late ACK.
    for i, (server, syn, ack, seq, acknowledgment, payload, types) in enumerate([
        (False,1,0,100,0,0,''), (True,1,1,500,101,0,''),
        (False,0,1,101,501,100,'1'), (True,0,1,501,201,200,'2,8,11,15,20'),
        (False,0,1,201,701,50,'20'), (True,0,1,701,251,0,'')], 1):
        r = dict.fromkeys(FIELDS, '')
        r.update({'frame.number':str(i), 'frame.time_epoch':str(10+i/1000),
                  'frame.len':str(54+payload), 'ip.len':str(40+payload),
                  'ip.src':'10.0.0.2' if server else '10.0.0.1',
                  'ip.dst':'10.0.0.1' if server else '10.0.0.2',
                  'tcp.srcport':'4433' if server else '50000',
                  'tcp.dstport':'50000' if server else '4433',
                  'tcp.stream':'0', 'tcp.flags.syn':str(syn), 'tcp.flags.ack':str(ack),
                  'tcp.seq_raw':str(seq), 'tcp.ack_raw':str(acknowledgment),
                  'tcp.len':str(payload), 'tls.handshake.type':types})
        rows.append(r)
    return rows


class MetricsTests(unittest.TestCase):
    def test_boundaries_totals_and_server_finished_not_endpoint(self):
        m = handshake_metrics(fixture(),4433)
        self.assertEqual([m[k+'_frame'] for k in ('syn','syn_ack','tcp_established','client_hello','client_finished')], [1,2,3,3,5])
        self.assertEqual(m['tcp_connect_wall_ms'],2)
        self.assertEqual(m['tls_from_pcap_wall_ms'],2)
        self.assertEqual(m['connection_handshake_wall_ms'],4)
        self.assertEqual(m['connection_handshake_packets'],5)
        self.assertEqual(m['connection_handshake_frame_bytes'],620)
        self.assertEqual(m['connection_handshake_ip_bytes'],550)
        self.assertEqual(m['connection_handshake_tcp_payload_bytes'],350)
        self.assertEqual(m['connection_handshake_retransmission_frames'],0)

    def test_retransmission_counts_once_and_includes_payload(self):
        rows=fixture()
        r=copy.deepcopy(rows[3]); r['frame.number']='5'; r['frame.time_epoch']='10.0045'
        r['tls.handshake.type']=''
        for k in ('tcp.analysis.retransmission','tcp.analysis.fast_retransmission','tcp.analysis.spurious_retransmission'): r[k]='1'
        rows[4]['frame.number']='6'; rows[5]['frame.number']='7'; rows.insert(4,r)
        m=handshake_metrics(rows,4433)
        self.assertEqual(m['connection_handshake_retransmission_frames'],1)
        self.assertEqual(m['connection_handshake_tcp_payload_bytes'],550)
        self.assertEqual(m['connection_handshake_packets'],6)

    def test_multiple_streams_require_explicit_selection(self):
        rows=fixture(); extra=copy.deepcopy(rows)
        for r in extra: r['tcp.stream']='1'
        with self.assertRaises(ValueError): handshake_metrics(rows+extra,4433)
        self.assertEqual(handshake_metrics(rows+extra,4433,0)['connection_handshake_packets'],5)

    def test_missing_boundaries_fail(self):
        for index in (0,1,2,4):
            rows=fixture(); rows.pop(index)
            with self.subTest(index=index), self.assertRaises(ValueError): handshake_metrics(rows,4433)

    def test_no_decryption_fails(self):
        rows=fixture(); rows[4]['tls.handshake.type']=''
        with self.assertRaisesRegex(ValueError,'Finished'): handshake_metrics(rows,4433)

    def test_syn_ack_timestamp_may_precede_syn_when_metric_boundaries_are_valid(self):
        rows = fixture()

        # Cross-direction capture timestamps may be slightly inverted even
        # though the protocol/frame order is unambiguous. SYN-ACK time is
        # not an endpoint of any published duration.
        rows[1]['frame.time_epoch'] = '9.999'

        m = handshake_metrics(rows, 4433)

        self.assertEqual(m['tcp_connect_wall_ms'], 2)
        self.assertEqual(m['tls_from_pcap_wall_ms'], 2)
        self.assertEqual(m['connection_handshake_wall_ms'], 4)
        self.assertEqual(
            [m[k + '_frame'] for k in (
                'syn',
                'syn_ack',
                'tcp_established',
                'client_hello',
                'client_finished',
            )],
            [1, 2, 3, 3, 5],
        )

    def test_bad_ack_ipv6_lengths_and_timestamp_fail(self):
        for index,key,value in ((2,'tcp.ack_raw','999'),(0,'ipv6.src','::1'),
                                (2,'ip.len','9999'),(4,'frame.time_epoch','9')):
            rows=fixture(); rows[index][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError): handshake_metrics(rows,4433)


if __name__=='__main__': unittest.main()

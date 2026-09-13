import unittest
from landmark_size_model import *
from core import der,seq,ALG

class ModelTests(unittest.TestCase):
    def test_hash_steps_all_small_populations(self):
        for n in range(1,1025):
            a,b=cover(0,n)[0]
            self.assertEqual(proof_hash_count(n),(b-a-1).bit_length())
    def test_power_of_two_boundary(self):
        for k in range(1,48):
            self.assertEqual(proof_hash_count(1<<k),k-1)
            self.assertEqual(proof_hash_count((1<<k)+1),k)
    def test_limits(self):
        self.assertEqual(proof_hash_count(MAXIMUM_SUPPORTED_N),47)
        with self.assertRaises(ValueError):model(b'fake tbs',1<<48)
        with self.assertRaises(ValueError):model(b'fake tbs',0)
    def test_tls_confirmation(self):
        self.assertEqual(tls_certificate_message_size([b'a']),14)
        self.assertEqual(tls_certificate_message_size([b'a'],mtc_confirmation=True),18)
    def test_der_transitions_and_exact_crossing(self):
        for length in (60,100,200,240,255,256,1900):
            tbs=der(48,b'x'*length)
            for n in (1,2,3,4,5,16,17,1024,MAXIMUM_SUPPORTED_N):
                row=model(tbs,n)
                self.assertEqual(row['tls_certificate_message_bytes'],len(certificate(tbs,proof(0,cover(0,n)[0][1],[bytes(32)]*proof_hash_count(n))))+17)
            target=model(tbs,17)['tls_certificate_message_bytes']
            self.assertEqual(crossover(tbs,target)['crossover_N'],17)
            self.assertEqual(crossover(tbs,target)['last_better_N'],16)
            self.assertEqual(crossover(tbs,100000)['status'],'NO_CROSSOVER_WITHIN_PROTOCOL_RANGE')
    def test_cross_at_first_point(self):
        self.assertEqual(crossover(b'abc',1)['crossover_N'],1)
        self.assertEqual(crossover(b'abc',1)['last_better_N'],'')

class ReferenceTests(unittest.TestCase):
    def test_no_tls_reference_never_claims_empirical_support(self):
        from crossover_extended import empirical,Inputs
        r=empirical(Inputs(),None,'ecdsa-p256',2,'hash',475,{})
        self.assertFalse(r['compatible'])
        self.assertFalse(r['TLS_signature_supported'])
        self.assertEqual(r['selected_reference_bytes'],475)
    def test_different_fixture_hash_retains_static_value(self):
        from crossover_extended import empirical,Inputs
        from pathlib import Path
        import tempfile,json
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            (root/'summary.csv').write_text('scenario,TLS_signature_supported,certificate_message_bytes_median_of_campaign_medians\necdsa-p256-d2,True,480\n')
            for name,data in [('manifest.json',{}),('environment.json',{}),('fixture_hashes.json',{'ecdsa-p256/depth-2/manifest.json':'different'})]:
                (root/name).write_text(json.dumps(data))
            r=empirical(Inputs(),root,'ecdsa-p256',2,'expected',475,{})
            self.assertFalse(r['compatible'])
            self.assertEqual(r['difference_bytes'],5)
            self.assertEqual(r['selected_reference_bytes'],475)
            self.assertIn('hashes differ',r['explanation'])

if __name__=='__main__':unittest.main()

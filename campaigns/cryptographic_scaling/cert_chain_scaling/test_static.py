import unittest
from size_analysis import tls_certificate_message_size
from config import DEPTHS,MTC_PROFILE_MAP,PROFILES
class StaticTests(unittest.TestCase):
 def test_tls_certificate_framing(self):
  self.assertEqual(tls_certificate_message_size([b"x"*100]),113)
  self.assertEqual(tls_certificate_message_size([b"x"*100,b"y"*200]),318)
 def test_matrix(self):
  self.assertEqual(DEPTHS,(2,3,4,5));self.assertEqual(len(PROFILES),9)
  self.assertEqual(MTC_PROFILE_MAP,{"ecdsa-p256":"classic","mldsa65":"pq"})
if __name__=="__main__":unittest.main()

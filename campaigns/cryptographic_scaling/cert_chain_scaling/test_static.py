import unittest
from size_analysis import tls_certificate_message_size,crossover_status
from config import DEPTHS,MTC_PROFILE_MAP,PROFILES
class StaticTests(unittest.TestCase):
 def test_tls_certificate_framing(self):
  self.assertEqual(tls_certificate_message_size([b"x"*100]),113)
  self.assertEqual(tls_certificate_message_size([b"x"*100,b"y"*200]),318)
 def test_crossover_distinguishes_missing_inputs_from_unsupported_profiles(self):
  for profile in MTC_PROFILE_MAP:
   self.assertEqual(crossover_status(profile,False,[],False),"MTC_FIXTURES_NOT_PROVIDED")
   self.assertEqual(crossover_status(profile,True,[],False),"MISSING_MTC_FIXTURES")
   self.assertEqual(crossover_status(profile,True,[{}],False),"OUTSIDE_SEARCH_RANGE")
   self.assertEqual(crossover_status(profile,True,[{}],True),"CROSSED")
  for supplied in (False,True):
   self.assertEqual(crossover_status("unknown-profile",supplied,[],False),"UNSUPPORTED_MTC_PROFILE")
 def test_matrix(self):
  self.assertEqual(DEPTHS,(2,3,4,5));self.assertEqual(len(PROFILES),9)
  self.assertEqual(MTC_PROFILE_MAP,{name:name for name in PROFILES})
if __name__=="__main__":unittest.main()

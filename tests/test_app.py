import unittest
from app import analyze_message
class MessageTests(unittest.TestCase):
 def test_urgency_signal(self): self.assertIn("urgency",analyze_message("URGENT act immediately")["signals"])
 def test_http_signal(self): self.assertIn("unencrypted_http",analyze_message("See http://example.org")["signals"])
 def test_links_not_fetched(self): self.assertFalse(analyze_message("See https://example.org")["urls_fetched"])
 def test_invalid_input(self):
  with self.assertRaises(ValueError): analyze_message(None)
 def test_score_capped(self): self.assertLessEqual(analyze_message("urgent immediately password verify your account wire transfer http://bit.ly/x")["score"],100)
if __name__=="__main__": unittest.main()

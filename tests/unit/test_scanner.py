import unittest
from scanner import clean_version

class TestScanner(unittest.TestCase):
    def test_clean_version(self):
        self.assertEqual(clean_version("1.2.3 (beta)"), "1.2.3")

if __name__ == '__main__':
    unittest.main()

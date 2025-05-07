import unittest

class TestNmap(unittest.TestCase):
    @unittest.skip("Example integration test")
    def test_scan(self):
        self.assertTrue(True)

if __name__ == '__main__':
    unittest.main()

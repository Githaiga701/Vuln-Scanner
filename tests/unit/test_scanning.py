import unittest
from unittest.mock import patch, MagicMock
from scanner import clean_version, get_cpe

class TestScannerFunctions(unittest.TestCase):
    def test_clean_version(self):
        self.assertEqual(clean_version("1.2.3 (beta)"), "1.2.3")
        self.assertEqual(clean_version(""), "")
    
    def test_cpe_generation(self):
        self.assertEqual(get_cpe("http", "2.4.49"), 
                       "cpe:2.3:a:*:apache:http_server:2.4.49")
        
    @patch('scanner.requests.get')
    def test_cve_lookup(self, mock_get):
        mock_response = MagicMock()
        mock_response.json.return_value = {"result": {"CVE_Items": []}}
        mock_get.return_value = mock_response
        
        from scanner import fetch_cves
        result = fetch_cves("http", "2.4.49")
        self.assertEqual(result, {"result": {"CVE_Items": []}})

    @patch('scanner.requests.get')
    def test_cve_lookup(self, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 200  # Add this
        mock_response.json.return_value = {"result": {"CVE_Items": []}}
        mock_get.return_value = mock_response

        from scanner import fetch_cves
        result = fetch_cves("http", "2.4.49")
        self.assertEqual(result, {"result": {"CVE_Items": []}})

if __name__ == '__main__':
    unittest.main()

    
#!/usr/bin/env python3
import nmap
import requests
import os
import re
import json
import logging
from time import sleep
from dotenv import load_dotenv

# --- Configuration --- #
load_dotenv()

# Initialize logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('scanner.log'),
        logging.StreamHandler()
    ]
)

# --- Constants --- #
CPE_MAPPINGS = {
    'http': 'apache:http_server',
    'https': 'apache:http_server',
    'ftp': 'vsftpd',
    'ssh': 'openssh'
}

# --- Core Functions --- #
def clean_version(version: str) -> str:
    """Sanitize version strings"""
    return re.sub(r'[^a-zA-Z0-9._-]', '', str(version).split()[0]) if version else ""

def get_cpe(service: str, version: str) -> str:
    """Generate valid CPE string"""
    base_product = CPE_MAPPINGS.get(service.lower(), service.lower())
    return f"cpe:2.3:a:*:{base_product}:{clean_version(version)}"

def fetch_cves(service: str, version: str) -> dict:
    """Query NVD API with better error handling"""
    if not service or service.lower() in ['tcpwrapped', 'unknown']:
        return None

    # Skip actual API call during tests
    if os.getenv('TESTING') == 'true':
        return {"result": {"CVE_Items": []}}

    try:
        cpe = get_cpe(service, version)
        url = f"https://services.nvd.nist.gov/rest/json/cves/1.0?cpeMatchString={cpe}"
        
        headers = {"apiKey": os.getenv("NVD_API_KEY", "")} if os.getenv("NVD_API_KEY") else {}
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            return response.json()
        return None
            
    except Exception as e:
        logging.error(f"API Error: {str(e)}")
        return None

class VulnerabilityPrioritizer:
    def __init__(self, scan_results: list):
        self.results = scan_results

    def _calculate_risk_score(self, cve: dict) -> float:
        """Calculate risk score (0-10) based on CVSS"""
        try:
            return float(cve.get('score', 0))
        except (TypeError, ValueError):
            return 0.0

    def prioritize(self) -> list:
        """Sort vulnerabilities by risk score"""
        prioritized = []
        for host in self.results:
            for port in host['ports']:
                for cve in port.get('cves', []):
                    prioritized.append({
                        'host': host['ip'],
                        'port': port['port'],
                        'service': port['service'],
                        'cve': cve['id'],
                        'risk_score': self._calculate_risk_score(cve),
                        'recommendation': f"Update {port['service']} to latest version"
                    })
        return sorted(prioritized, key=lambda x: x['risk_score'], reverse=True)

def run_scan(target: str) -> list:
    """Perform the vulnerability scan"""
    scanner = nmap.PortScanner()
    
    try:
        logging.info(f"Scanning {target}...")
        scanner.scan(hosts=target, arguments='-sV -T4')
        
        results = []
        for host in scanner.all_hosts():
            host_data = {
                'ip': host,
                'hostname': scanner[host].hostname() or '',
                'ports': []
            }
            
            for proto in scanner[host].all_protocols():
                for port, info in scanner[host][proto].items():
                    service = info['name']
                    version = info.get('version', '')
                    
                    cves = []
                    if service.lower() not in ['tcpwrapped', 'unknown']:
                        cve_data = fetch_cves(service, version)
                        if cve_data and 'result' in cve_data:
                            cves = [
                                {
                                    'id': cve['cve']['CVE_data_meta']['ID'],
                                    'score': cve['impact'].get('baseMetricV3', {}).get('cvssV3', {}).get('baseScore', 'N/A')
                                }
                                for cve in cve_data['result']['CVE_Items'][:3]
                            ]
                    
                    host_data['ports'].append({
                        'port': port,
                        'service': service,
                        'version': version,
                        'cves': cves
                    })
            
            results.append(host_data)
        
        return results
        
    except Exception as e:
        logging.error(f"Scan failed: {str(e)}")
        return None

def main():
    print("\n=== Vulnerability Scanner ===")
    
    while True:
        try:
            target = input("\nEnter target IP or range (or 'quit' to exit): ").strip()
            
            if target.lower() in ['quit', 'exit']:
                break
                
            if not target:
                print("Please enter a valid target")
                continue
                
            scan_results = run_scan(target)
            
            if scan_results:
                print("\nScan Results:")
                for host in scan_results:
                    print(f"\nHost: {host['ip']} ({host['hostname']})")
                    for port in host['ports']:
                        print(f"  Port {port['port']}: {port['service']} {port['version']}")
                        if port['cves']:
                            for cve in port['cves']:
                                print(f"    CVE: {cve['id']} (CVSS: {cve['score']})")
                
                # Prioritize results
                prioritizer = VulnerabilityPrioritizer(scan_results)
                critical_vulns = prioritizer.prioritize()
                
                print("\n[!] Critical Vulnerabilities:")
                for vuln in critical_vulns[:5]:  # Show top 5
                    print(f"- {vuln['cve']} (Risk: {vuln['risk_score']:.1f}) on {vuln['host']}:{vuln['port']}")
                
                # Save all data
                with open('scan_results.json', 'w') as f:
                    json.dump({
                        'scan': scan_results,
                        'prioritized': critical_vulns
                    }, f, indent=2)
                print("\nResults saved to scan_results.json")
            
        except KeyboardInterrupt:
            print("\nScan cancelled by user")
            break
        except Exception as e:
            print(f"\nError: {str(e)}")

if __name__ == "__main__":
    main()
#!/usr/bin/env python3
import nmap
import requests
import os
import re
import json
import logging
from time import sleep
from dotenv import load_dotenv

# --- Configuration --- #
load_dotenv()

# Initialize logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('scanner.log'),
        logging.StreamHandler()
    ]
)

# --- Constants --- #
CPE_MAPPINGS = {
    'http': 'apache:http_server',
    'https': 'apache:http_server',
    'ftp': 'vsftpd',
    'ssh': 'openssh'
}

# --- Core Functions --- #
def clean_version(version: str) -> str:
    """Sanitize version strings"""
    return re.sub(r'[^a-zA-Z0-9._-]', '', str(version).split()[0]) if version else ""

def get_cpe(service: str, version: str) -> str:
    """Generate valid CPE string"""
    base_product = CPE_MAPPINGS.get(service.lower(), service.lower())
    return f"cpe:2.3:a:*:{base_product}:{clean_version(version)}"

def fetch_cves(service: str, version: str) -> dict:
    """Query NVD API with better error handling"""
    if not service or service.lower() in ['tcpwrapped', 'unknown']:
        return None

    # Skip actual API call during tests
    if os.getenv('TESTING') == 'true':
        return {"result": {"CVE_Items": []}}

    try:
        cpe = get_cpe(service, version)
        url = f"https://services.nvd.nist.gov/rest/json/cves/1.0?cpeMatchString={cpe}"
        
        headers = {"apiKey": os.getenv("NVD_API_KEY", "")} if os.getenv("NVD_API_KEY") else {}
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            return response.json()
        return None
            
    except Exception as e:
        logging.error(f"API Error: {str(e)}")
        return None

class VulnerabilityPrioritizer:
    def __init__(self, scan_results: list):
        self.results = scan_results

    def _calculate_risk_score(self, cve: dict) -> float:
        """Calculate risk score (0-10) based on CVSS"""
        try:
            return float(cve.get('score', 0))
        except (TypeError, ValueError):
            return 0.0

    def prioritize(self) -> list:
        """Sort vulnerabilities by risk score"""
        prioritized = []
        for host in self.results:
            for port in host['ports']:
                for cve in port.get('cves', []):
                    prioritized.append({
                        'host': host['ip'],
                        'port': port['port'],
                        'service': port['service'],
                        'cve': cve['id'],
                        'risk_score': self._calculate_risk_score(cve),
                        'recommendation': f"Update {port['service']} to latest version"
                    })
        return sorted(prioritized, key=lambda x: x['risk_score'], reverse=True)

def run_scan(target: str) -> list:
    """Perform the vulnerability scan"""
    scanner = nmap.PortScanner()
    
    try:
        logging.info(f"Scanning {target}...")
        scanner.scan(hosts=target, arguments='-sV -T4')
        
        results = []
        for host in scanner.all_hosts():
            host_data = {
                'ip': host,
                'hostname': scanner[host].hostname() or '',
                'ports': []
            }
            
            for proto in scanner[host].all_protocols():
                for port, info in scanner[host][proto].items():
                    service = info['name']
                    version = info.get('version', '')
                    
                    cves = []
                    if service.lower() not in ['tcpwrapped', 'unknown']:
                        cve_data = fetch_cves(service, version)
                        if cve_data and 'result' in cve_data:
                            cves = [
                                {
                                    'id': cve['cve']['CVE_data_meta']['ID'],
                                    'score': cve['impact'].get('baseMetricV3', {}).get('cvssV3', {}).get('baseScore', 'N/A')
                                }
                                for cve in cve_data['result']['CVE_Items'][:3]
                            ]
                    
                    host_data['ports'].append({
                        'port': port,
                        'service': service,
                        'version': version,
                        'cves': cves
                    })
            
            results.append(host_data)
        
        return results
        
    except Exception as e:
        logging.error(f"Scan failed: {str(e)}")
        return None

def main():
    print("\n=== Vulnerability Scanner ===")
    
    while True:
        try:
            target = input("\nEnter target IP or range (or 'quit' to exit): ").strip()
            
            if target.lower() in ['quit', 'exit']:
                break
                
            if not target:
                print("Please enter a valid target")
                continue
                
            scan_results = run_scan(target)
            
            if scan_results:
                print("\nScan Results:")
                for host in scan_results:
                    print(f"\nHost: {host['ip']} ({host['hostname']})")
                    for port in host['ports']:
                        print(f"  Port {port['port']}: {port['service']} {port['version']}")
                        if port['cves']:
                            for cve in port['cves']:
                                print(f"    CVE: {cve['id']} (CVSS: {cve['score']})")
                
                # Prioritize results
                prioritizer = VulnerabilityPrioritizer(scan_results)
                critical_vulns = prioritizer.prioritize()
                
                print("\n[!] Critical Vulnerabilities:")
                for vuln in critical_vulns[:5]:  # Show top 5
                    print(f"- {vuln['cve']} (Risk: {vuln['risk_score']:.1f}) on {vuln['host']}:{vuln['port']}")
                
                # Save all data
                with open('scan_results.json', 'w') as f:
                    json.dump({
                        'scan': scan_results,
                        'prioritized': critical_vulns
                    }, f, indent=2)
                print("\nResults saved to scan_results.json")
            
        except KeyboardInterrupt:
            print("\nScan cancelled by user")
            break
        except Exception as e:
            print(f"\nError: {str(e)}")

if __name__ == "__main__":
    main()
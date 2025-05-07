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

    try:
        cpe = get_cpe(service, version)
        url = f"https://services.nvd.nist.gov/rest/json/cves/1.0?cpeMatchString={cpe}"
        
        # Try with and without API key
        headers = {"apiKey": os.getenv("NVD_API_KEY", "")} if os.getenv("NVD_API_KEY") else {}
        
        try:
            response = requests.get(url, headers=headers, timeout=10)
            return response.json() if response.status_code == 200 else None
        except requests.exceptions.SSLError:
            # Fallback to non-SSL if needed
            url = url.replace('https://', 'http://')
            response = requests.get(url, headers=headers, timeout=10)
            return response.json() if response.status_code == 200 else None
            
    except Exception as e:
        logging.error(f"API Connection Error: {str(e)}")
        return None

def run_scan(target: str) -> dict:
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
                                for cve in cve_data['result']['CVE_Items'][:3]  # Show top 3
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
                
            results = run_scan(target)
            
            if results:
                print("\nScan Results:")
                for host in results:
                    print(f"\nHost: {host['ip']} ({host['hostname']})")
                    for port in host['ports']:
                        print(f"  Port {port['port']}: {port['service']} {port['version']}")
                        if port['cves']:
                            for cve in port['cves']:
                                print(f"    CVE: {cve['id']} (CVSS: {cve['score']})")
                        else:
                            print("    No CVEs found")
                
                # Save to file
                with open('scan_results.json', 'w') as f:
                    json.dump(results, f, indent=2)
                print("\nResults saved to scan_results.json")
            
        except KeyboardInterrupt:
            print("\nScan cancelled by user")
            break
        except Exception as e:
            print(f"\nError: {str(e)}")

if __name__ == "__main__":
    main()
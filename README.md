
# Vulnerability Scanner

## Features

- Parallel network scanning
- CVE detection via NVD API
- JSON output

## Usage

```bash
# Basic scan
python scanner.py -t 192.168.1.1

# Full network scan
python scanner.py -t 192.168.1.0/24 -j 8 -o results.json

## Configuration
Edit `config.ini` for scan parameters

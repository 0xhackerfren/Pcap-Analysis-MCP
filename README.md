# PCAP Analysis MCP

> **POC Project** - A proof-of-concept MCP server for network forensics. Built to solve problems I needed, shared in case it's useful. No active support or maintenance - use as you wish.

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Network forensics MCP (Model Context Protocol) server providing AI agents with packet capture analysis capabilities.

## What It Does

- **60+ Analysis Tools** (63 total) across 8 categories
- **Attack Detection** - CVE patterns, port scans, web exploits
- **Timeline Reconstruction** - Cyber Kill Chain and MITRE ATT&CK mapping
- **IoC Extraction** - IPs, domains with optional enrichment
- **Protocol Analysis** - HTTP, DNS, SMB, FTP, SSH, RDP, SMTP, TLS
- **C2 Detection** - Reverse shells, beacons, data exfiltration
- **HTML Reporting** - Investigation reports

## Installation

```bash
git clone https://github.com/wzsx150/Pcap-Analysis-MCP.git
cd pcap-analysis-mcp
pip install -e .

# With all optional deps
pip install -e ".[full]"
```

### Requirements

- Python 3.9+
- scapy >= 2.5.0 (required)
- pandas, jinja2, requests (optional)

## Usage

### As MCP Server

Add to your MCP config:

```json
{
  "mcpServers": {
    "pcap-analysis": {
      "command": "python",
      "args": ["-m", "pcap_analysis_mcp"],
      "transport": "stdio"
    }
  }
}
```

> **Notes**
> - Running without arguments starts the MCP server by default; the `--server` flag is optional (kept for compatibility).
> - On Windows, if `python` is not in PATH, point `command` to your interpreter (e.g. `py -3.10`) or use its full absolute path.
> - Supported MCP protocol versions: `2024-11-05`, `2025-03-26`, `2025-06-18` — negotiated automatically during `initialize`.

### Command Line

```bash
# Run as MCP server (default behavior, no arguments needed)
python -m pcap_analysis_mcp
python -m pcap_analysis_mcp --server    # equivalent, kept for compatibility

# Analyze a PCAP file directly
python -m pcap_analysis_mcp --analyze capture.pcap --output report.html

# Check installation
python -m pcap_analysis_mcp --check
```

### Python API

```python
from pcap_analysis_mcp import PCAPAnalysisMCP

mcp = PCAPAnalysisMCP()
mcp.load_pcap("capture.pcap")

# Get summary
print(mcp.get_summary())

# Detect attacks
exploits = mcp.detect_web_exploits()
scans = mcp.detect_port_scan()

# Build timeline
timeline = mcp.build_attack_timeline()

# Generate report
mcp.generate_html_report("report.html")
```

## Tools

### Standard MCP (3 tools)
`list_capabilities`, `get_documentation`, `check_installation`

### Core Analysis (10 tools)
`load_pcap`, `get_summary`, `get_conversations`, `get_protocols`, `get_statistics`, `filter_packets`, `export_packets`, `get_packet_details`, `search_payload`, `get_unique_values`

### Reconnaissance (8 tools)
`detect_port_scan`, `get_open_ports`, `detect_host_discovery`, `detect_service_scan`, `get_first_responder`, `analyze_scan_pattern`, `identify_scanner`, `get_scan_summary`

### HTTP/Web (10 tools)
`extract_http_requests`, `extract_http_responses`, `get_http_sessions`, `detect_web_exploits`, `extract_post_payloads`, `extract_server_info`, `find_file_transfers`, `detect_webshells`, `get_user_agents`, `analyze_http_timeline`

### Attack Timeline (6 tools)
`build_attack_timeline`, `identify_attack_phases`, `find_initial_access`, `find_initial_foothold`, `detect_lateral_movement`, `map_to_mitre`

### C2 Detection (6 tools)
`detect_reverse_shells`, `analyze_shell_traffic`, `detect_c2_beacons`, `detect_data_exfil`, `identify_c2_channels`, `extract_shell_commands`

### IoC Enrichment (8 tools)
`extract_all_iocs`, `enrich_ip`, `check_virustotal`, `check_abuseipdb`, `check_otx`, `defang_iocs`, `export_iocs_stix`, `get_threat_context`

### Protocol Analysis (7 tools)
`analyze_dns`, `analyze_smb`, `analyze_ftp`, `analyze_ssh`, `analyze_rdp`, `analyze_smtp`, `analyze_tls`

### Reporting (5 tools)
`generate_html_report`, `generate_executive_summary`, `generate_timeline_html`, `generate_ioc_report`, `export_findings_json`

## Detection Patterns

Includes patterns for:
- CVE-2024-4577 (PHP CGI), CVE-2021-44228 (Log4Shell), CVE-2021-41773 (Apache)
- SQL injection, XSS, command injection, path traversal
- Webshells, SSRF, XXE, LFI, deserialization
- Reverse shells (bash, netcat, python, powershell)
- C2 beacons and tunneling

## Project Structure

```
pcap-analysis-mcp/
  src/pcap_analysis_mcp/   # Main package
    data/                  # Detection patterns (JSON, bundled into the wheel)
    templates/             # HTML report templates (bundled into the wheel)
  examples/                # Usage examples
```

## License

MIT - do what you want with it.

## Disclaimer

This is a POC project. No warranties, no support, no guarantees. Works for my use cases - might work for yours.

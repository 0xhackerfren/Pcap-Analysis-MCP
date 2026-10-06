# Changelog

## [1.0.3] - 2026-10-06

Tool correctness release - fixes reported by MCP client testing.

### Fixed
- `generate_timeline_html` and `generate_ioc_report` previously returned
  `{"path": ...}` without writing any file (fake success); both now write
  real HTML reports via a shared `_write_html_report` helper (pure stdlib,
  no jinja2 dependency)
- `get_unique_values` no longer silently returns empty results for invalid
  `value_type` values; unknown values now return an explicit error listing
  valid options

### Changed
- `get_unique_values`: added `ports` support (TCP/UDP sport/dport) and alias
  normalization (`ip`/`ips`, `port`/`ports`, `domain`/`domains`,
  case-insensitive)
- `detect_webshells`: replaced the single fixed regex with 6 named signature
  families (classic PHP one-liners, command-exec functions, `c99`/`r57`/`wso`/
  `b374k`, Godzilla `pass=`/`key=`, China Chopper `cmd`/`z0`) plus a
  structural heuristic flagging the same `.php` endpoint POSTed >= 3 times
  (catches encrypted webshells like Godzilla/Behinder with no cleartext
  markers); returns `webshell_suspected`, `signatures_matched`,
  `suspicious_endpoints` and match snippets

## [1.0.2] - 2026-10-06

Packaging fix - full detection data now bundled for non-editable installs.

### Fixed
- Bundled `data/*.json` and `templates/*.html` into the wheel; non-editable
  installs previously fell back to built-in defaults (6 exploit pattern
  types instead of 12) and lost the HTML report templates

### Changed
- Moved `data/` and `templates/` inside the package
  (`src/pcap_analysis_mcp/`); data paths now resolve package-first with
  fallback to the project root

## [1.0.1] - 2026-10-06

Bug fix release - MCP protocol compliance and client compatibility.

### Fixed
- tools/list: added required `inputSchema` to all 63 tools (auto-generated
  from tool signatures); clients previously rejected the entire tool list
- JSON-RPC: notifications (e.g. `notifications/initialized`) no longer
  receive an invalid `id: null` error response
- `generate_html_report` falls back to the embedded template when
  `report_base.html` is missing

### Changed
- initialize: protocolVersion negotiation (2024-11-05 / 2025-03-26 /
  2025-06-18) and `instructions` field
- tools/call: unknown tool / invalid arguments return -32602; execution
  failures return an `isError` result per spec
- stdio: force UTF-8 streams (Windows GBK default), skip malformed lines
  instead of exiting, support JSON-RPC batches, `ping`, and lenient
  `resources/list` / `prompts/list` handling
- CLI: runs as MCP server by default (no arguments needed)

## [1.0.0] - 2024-12-04

Initial release - POC for network forensics via MCP.

### Features
- 50+ analysis tools across 8 categories
- Attack detection (CVEs, scans, exploits)
- Timeline reconstruction with MITRE ATT&CK mapping
- IoC extraction and optional enrichment
- Protocol analysis (HTTP, DNS, SMB, FTP, SSH, RDP, SMTP, TLS)
- C2/reverse shell detection
- HTML report generation

### Detection Patterns
- CVE-2024-4577, CVE-2021-44228, CVE-2021-41773
- SQL injection, XSS, command injection, path traversal
- Webshells, SSRF, XXE, LFI, deserialization
- Reverse shell patterns (bash, netcat, python, powershell)
- C2 beacon detection

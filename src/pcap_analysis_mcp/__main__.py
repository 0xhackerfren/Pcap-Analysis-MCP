# -*- coding: utf-8 -*-
"""
PCAP Analysis MCP - Main Entry Point

Usage:
    # As MCP server (stdio transport)
    python -m pcap_analysis_mcp
    python -m pcap_analysis_mcp --server
    
    # Analyze PCAP file directly
    python -m pcap_analysis_mcp --analyze capture.pcap --output report.html
    
    # Show capabilities
    python -m pcap_analysis_mcp --capabilities
"""

import sys
import json
import argparse

from pcap_analysis_mcp.core import PCAPAnalysisMCP


def main():
    """Main entry point for PCAP Analysis MCP."""
    parser = argparse.ArgumentParser(
        description="PCAP Analysis MCP Server - Enterprise Network Forensics",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m pcap_analysis_mcp --server          Run as MCP server
  python -m pcap_analysis_mcp --analyze file.pcap  Analyze PCAP file
  python -m pcap_analysis_mcp --capabilities    Show available tools
        """
    )
    parser.add_argument(
        "--server",
        action="store_true",
        help="Run as MCP server (stdio transport)"
    )
    parser.add_argument(
        "--analyze",
        type=str,
        metavar="PCAP",
        help="Analyze PCAP file and generate report"
    )
    parser.add_argument(
        "--output",
        type=str,
        default="report.html",
        metavar="FILE",
        help="Output path for report (default: report.html)"
    )
    parser.add_argument(
        "--json-output",
        type=str,
        metavar="FILE",
        help="Also export findings as JSON to this path"
    )
    parser.add_argument(
        "--capabilities",
        action="store_true",
        help="Show all available tools and capabilities"
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Check dependencies and installation"
    )
    parser.add_argument(
        "--version",
        action="store_true",
        help="Show version information"
    )
    
    args = parser.parse_args()
    
    mcp = PCAPAnalysisMCP()
    
    if args.version:
        print(f"{mcp.name} v{mcp.version}")
        return 0
    
    if args.check:
        status = mcp.check_installation()
        print(f"PCAP Analysis MCP Installation Check")
        print(f"=====================================")
        print(f"Ready: {status['ready']}")
        print(f"\nDependencies:")
        for dep, info in status['dependencies'].items():
            status_str = "[OK]" if info['installed'] else "[MISSING]"
            req_str = "(required)" if info['required'] else "(optional)"
            print(f"  {status_str} {dep} {req_str}")
        if not status['ready']:
            print(f"\nInstall required dependencies:")
            print(f"  {status['install_command']}")
        return 0 if status['ready'] else 1
    
    if args.capabilities:
        caps = mcp.list_capabilities()
        print(json.dumps(caps, indent=2))
        return 0
    
    if args.server:
        mcp.run_server()
        return 0
    
    if args.analyze:
        print(f"Loading {args.analyze}...")
        result = mcp.load_pcap(args.analyze)
        
        if "error" in result:
            print(f"Error: {result['error']}")
            return 1
        
        print(f"Loaded {result['metadata']['total_packets']} packets")
        print(f"Duration: {result['metadata']['duration_seconds']} seconds")
        
        # Get summary
        summary = mcp.get_summary()
        print(f"\nUnique IPs: {summary.get('unique_ips', 0)}")
        print(f"Protocols: {summary.get('protocols', {})}")
        
        # Detect exploits
        exploits = mcp.detect_web_exploits()
        print(f"\nExploits detected: {exploits['exploits_detected']}")
        for f in exploits.get('findings', []):
            print(f"  [{f['severity'].upper()}] {f['name']}")
        
        # Detect port scans
        scans = mcp.detect_port_scan()
        if scans['scan_detected']:
            print(f"\nPort scans detected:")
            for s in scans['scanners']:
                print(f"  Scanner: {s['scanner_ip']} ({s['ports_scanned']} ports)")
        
        # Generate HTML report
        report = mcp.generate_html_report(args.output)
        if report.get('success'):
            print(f"\nHTML report saved: {report['path']}")
        else:
            print(f"\nReport error: {report.get('error')}")
        
        # Optional JSON export
        if args.json_output:
            json_result = mcp.export_findings_json(args.json_output)
            if json_result.get('success'):
                print(f"JSON export saved: {json_result['path']}")
        
        return 0
    
    # 默认行为：作为 MCP 服务器运行（stdio 传输）
    # 客户端配置 "args": ["-m", "pcap_analysis_mcp"] 无需额外参数即可启动
    mcp.run_server()
    return 0


if __name__ == "__main__":
    sys.exit(main())


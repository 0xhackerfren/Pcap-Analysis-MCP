# -*- coding: utf-8 -*-
"""
PCAP Analysis MCP - Network Forensics for AI Agents

A proof-of-concept MCP server providing 50+ tools for packet capture
analysis, attack detection, timeline reconstruction, and IoC extraction.
"""

from pcap_analysis_mcp.core import PCAPAnalysisMCP
from pcap_analysis_mcp.protocol import MCPProtocol

__version__ = "1.0.3"
__author__ = "PCAP Analysis MCP Project"
__license__ = "MIT"

__all__ = [
    "PCAPAnalysisMCP",
    "MCPProtocol",
    "__version__",
]


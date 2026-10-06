# -*- coding: utf-8 -*-
"""
Core PCAP Analysis MCP Implementation

Enterprise-grade network forensics MCP providing 50+ tools for:
- Packet analysis and filtering
- Attack detection (CVEs, scans, exploits)
- Timeline reconstruction (Cyber Kill Chain, MITRE ATT&CK)
- IoC extraction and enrichment
- Protocol-specific analysis
- Professional HTML reporting
"""

import json
import re
import os
import logging
import inspect
import types
import typing
from pathlib import Path
from typing import Any, Dict, List, Optional, Callable
from datetime import datetime
from collections import defaultdict
from html import escape as escape_html

from pcap_analysis_mcp.protocol import MCPProtocol
from pcap_analysis_mcp.constants import (
    DATA_DIR,
    TEMPLATES_DIR,
    DEFAULT_EXPLOIT_PATTERNS,
    DEFAULT_C2_INDICATORS,
    DEFAULT_MITRE_MAPPING,
    MCP_PROTOCOL_VERSION,
    SERVER_INSTRUCTIONS,
    SUPPORTED_PROTOCOL_VERSIONS,
    MCP_SERVER_NAME,
    MCP_SERVER_VERSION,
    DEFAULT_PORT_SCAN_THRESHOLD,
    DEFAULT_WEBSHELL_POST_THRESHOLD,
    DEFAULT_BEACON_INTERVAL_THRESHOLD,
    DEFAULT_EXFIL_BYTES_THRESHOLD,
    PRIVATE_IP_PREFIXES,
)

# Configure logging for Windows console compatibility (ASCII only)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("pcap-analysis-mcp")

# =============================================================================
# DEPENDENCY CHECKS
# =============================================================================

try:
    from scapy.all import (
        rdpcap, wrpcap, IP, TCP, UDP, ICMP, DNS, DNSQR, DNSRR,
        ARP, Ether, Raw, conf
    )
    conf.verb = 0  # Suppress Scapy warnings
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logger.warning("scapy not installed. Install with: pip install scapy")
    # Create placeholders for type hints
    IP = TCP = UDP = ICMP = DNS = DNSQR = DNSRR = ARP = Ether = Raw = None

try:
    import pandas as pd
    PANDAS_AVAILABLE = True
except ImportError:
    PANDAS_AVAILABLE = False

try:
    from jinja2 import Environment, FileSystemLoader, BaseLoader
    JINJA_AVAILABLE = True
except ImportError:
    JINJA_AVAILABLE = False

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


# =============================================================================
# INPUT SCHEMA 生成（JSON Schema）
# =============================================================================

# Python 基础类型 -> JSON Schema 类型映射
# 注意：bool 是 int 的子类，因此用字典按精确类型匹配，避免 bool 被误判为 integer
_PRIMITIVE_SCHEMA_TYPES: Dict[type, str] = {
    str: "string",
    int: "integer",
    float: "number",
    bool: "boolean",
}


def _annotation_to_schema(annotation: Any) -> Dict[str, Any]:
    """
    将 Python 类型标注转换为对应的 JSON Schema 片段。

    Args:
        annotation: 函数参数的类型标注（可为 None 或 inspect.Parameter.empty）。

    Returns:
        JSON Schema 片段；无法识别时返回空 dict（表示不做类型约束，接受任意值）。
    """
    if annotation is None or annotation is inspect.Parameter.empty:
        return {}

    # 联合类型（Optional[X] / X | None）：剔除 None 分支后递归处理
    origin = typing.get_origin(annotation)
    union_type = getattr(types, "UnionType", None)  # Python 3.10+ 的 X | Y 语法
    if origin is typing.Union or (union_type is not None and origin is union_type):
        args = [a for a in typing.get_args(annotation) if a is not type(None)]
        if len(args) == 1:
            return _annotation_to_schema(args[0])
        return {}  # 多类型联合：不做约束

    if origin is list:
        return {"type": "array", "items": {}}
    if origin is dict:
        return {"type": "object"}
    if origin is tuple:
        return {"type": "array"}

    schema_type = _PRIMITIVE_SCHEMA_TYPES.get(annotation)
    if schema_type:
        return {"type": schema_type}
    return {}


def build_input_schema(func: Callable) -> Dict[str, Any]:
    """
    根据函数签名自动生成 MCP 规范要求的 inputSchema（JSON Schema 对象）。

    MCP 规范规定 tools/list 返回的每个工具必须包含 inputSchema
    （type 为 object 的 JSON Schema），缺失会导致客户端（基于 zod 校验的 SDK）
    拒绝加载全部工具。

    Args:
        func: 已绑定的工具方法（绑定方法的签名会自动排除 self）。

    Returns:
        形如 {"type": "object", "properties": {...}, "required": [...]} 的 schema。
    """
    properties: Dict[str, Any] = {}
    required: List[str] = []

    try:
        signature = inspect.signature(func)
    except (TypeError, ValueError):
        # 无法内省签名时，返回最宽松的合法 schema
        return {"type": "object", "properties": {}}

    for param_name, param in signature.parameters.items():
        # *args / **kwargs 不映射为 schema 属性
        if param.kind in (param.VAR_POSITIONAL, param.VAR_KEYWORD):
            continue

        schema = _annotation_to_schema(param.annotation)
        if not schema and param.default is not inspect.Parameter.empty and param.default is not None:
            # 无类型标注时，尝试从默认值推断类型
            inferred = _PRIMITIVE_SCHEMA_TYPES.get(type(param.default))
            if inferred:
                schema = {"type": inferred}

        properties[param_name] = schema
        # 无默认值的参数视为必填
        if param.default is inspect.Parameter.empty:
            required.append(param_name)

    result: Dict[str, Any] = {"type": "object", "properties": properties}
    if required:
        result["required"] = required
    return result


class PCAPAnalysisMCP:
    """
    PCAP Analysis MCP Server
    
    Enterprise-grade network forensics with 50+ analysis tools.
    
    Attributes:
        name: Server name identifier.
        version: Server version string.
        packets: Loaded packet list from PCAP file.
        pcap_path: Path to currently loaded PCAP.
        pcap_metadata: Metadata about loaded PCAP file.
    
    Example:
        >>> mcp = PCAPAnalysisMCP()
        >>> mcp.load_pcap("capture.pcap")
        >>> mcp.detect_web_exploits()
    """
    
    def __init__(self):
        """Initialize MCP with data loading."""
        self.name = MCP_SERVER_NAME
        self.version = MCP_SERVER_VERSION
        
        # State
        self.packets = None
        self.pcap_path: Optional[Path] = None
        self.pcap_metadata: Dict[str, Any] = {}
        self._cache: Dict[str, Any] = {}
        
        # Load detection patterns
        self.exploit_patterns = self._load_data("exploit_patterns.json", DEFAULT_EXPLOIT_PATTERNS)
        self.c2_indicators = self._load_data("c2_indicators.json", DEFAULT_C2_INDICATORS)
        self.mitre_mapping = self._load_data("mitre_mapping.json", DEFAULT_MITRE_MAPPING)
        
        # Build tool registry
        self._tools = self._build_tool_registry()
    
    def _load_data(self, filename: str, default: Dict) -> Dict:
        """
        Load JSON data file with fallback to default.
        
        Args:
            filename: Name of JSON file in data directory.
            default: Default dict to use if file not found.
            
        Returns:
            Loaded data dict or default.
        """
        path = DATA_DIR / filename
        if path.exists():
            try:
                return json.loads(path.read_text(encoding="utf-8"))
            except Exception as e:
                logger.warning(f"Failed to load {filename}: {e}")
        return default
    
    def _build_tool_registry(self) -> Dict[str, Callable]:
        """Build registry of all available tools."""
        return {
            # Standard MCP
            "list_capabilities": self.list_capabilities,
            "get_documentation": self.get_documentation,
            "check_installation": self.check_installation,
            # Core Analysis
            "load_pcap": self.load_pcap,
            "get_summary": self.get_summary,
            "get_conversations": self.get_conversations,
            "get_protocols": self.get_protocols,
            "get_statistics": self.get_statistics,
            "filter_packets": self.filter_packets,
            "export_packets": self.export_packets,
            "get_packet_details": self.get_packet_details,
            "search_payload": self.search_payload,
            "get_unique_values": self.get_unique_values,
            # Reconnaissance
            "detect_port_scan": self.detect_port_scan,
            "get_open_ports": self.get_open_ports,
            "detect_host_discovery": self.detect_host_discovery,
            "detect_service_scan": self.detect_service_scan,
            "get_first_responder": self.get_first_responder,
            "analyze_scan_pattern": self.analyze_scan_pattern,
            "identify_scanner": self.identify_scanner,
            "get_scan_summary": self.get_scan_summary,
            # HTTP/Web
            "extract_http_requests": self.extract_http_requests,
            "extract_http_responses": self.extract_http_responses,
            "get_http_sessions": self.get_http_sessions,
            "detect_web_exploits": self.detect_web_exploits,
            "extract_post_payloads": self.extract_post_payloads,
            "extract_server_info": self.extract_server_info,
            "find_file_transfers": self.find_file_transfers,
            "detect_webshells": self.detect_webshells,
            "get_user_agents": self.get_user_agents,
            "analyze_http_timeline": self.analyze_http_timeline,
            # Timeline
            "build_attack_timeline": self.build_attack_timeline,
            "identify_attack_phases": self.identify_attack_phases,
            "find_initial_access": self.find_initial_access,
            "find_initial_foothold": self.find_initial_foothold,
            "detect_lateral_movement": self.detect_lateral_movement,
            "map_to_mitre": self.map_to_mitre,
            # C2
            "detect_reverse_shells": self.detect_reverse_shells,
            "analyze_shell_traffic": self.analyze_shell_traffic,
            "detect_c2_beacons": self.detect_c2_beacons,
            "detect_data_exfil": self.detect_data_exfil,
            "identify_c2_channels": self.identify_c2_channels,
            "extract_shell_commands": self.extract_shell_commands,
            # IoC
            "extract_all_iocs": self.extract_all_iocs,
            "enrich_ip": self.enrich_ip,
            "check_virustotal": self.check_virustotal,
            "check_abuseipdb": self.check_abuseipdb,
            "check_otx": self.check_otx,
            "defang_iocs": self.defang_iocs,
            "export_iocs_stix": self.export_iocs_stix,
            "get_threat_context": self.get_threat_context,
            # Protocol
            "analyze_dns": self.analyze_dns,
            "analyze_smb": self.analyze_smb,
            "analyze_ftp": self.analyze_ftp,
            "analyze_ssh": self.analyze_ssh,
            "analyze_rdp": self.analyze_rdp,
            "analyze_smtp": self.analyze_smtp,
            "analyze_tls": self.analyze_tls,
            # Reporting
            "generate_html_report": self.generate_html_report,
            "generate_executive_summary": self.generate_executive_summary,
            "generate_timeline_html": self.generate_timeline_html,
            "generate_ioc_report": self.generate_ioc_report,
            "export_findings_json": self.export_findings_json,
        }
    
    # =========================================================================
    # MCP PROTOCOL METHODS
    # =========================================================================
    
    def handle_request(self, request: Dict) -> Optional[Dict]:
        """
        处理单条 MCP 消息（JSON-RPC 2.0）。

        通知（无 id 的消息）按规范不产生任何应答，返回 None；
        请求（id 为字符串/数字）必须返回应答字典。

        Args:
            request: 客户端发来的 JSON-RPC 消息。

        Returns:
            JSON-RPC 应答字典；通知或无法处理的消息返回 None。
        """
        if not isinstance(request, dict):
            logger.warning(f"Ignoring non-object message: {request!r}")
            return None

        method = request.get("method", "")
        req_id = request.get("id")
        # JSON-RPC 2.0：id 为字符串/数字才是"请求"；无 id 或 id 为 null 视为通知
        # （bool 是 int 子类，需显式排除，避免 id: true 被当成请求）
        is_request = isinstance(req_id, (str, int, float)) and not isinstance(req_id, bool)

        params = request.get("params")
        if not isinstance(params, dict):
            params = {}

        # 所有通知（notifications/initialized、cancelled、roots/list_changed 等）
        # 均按规范静默忽略，绝不回写任何响应（回写 id 为 null 的响应会导致客户端校验失败）
        if not is_request:
            if method == "notifications/initialized":
                logger.info("Received notifications/initialized")
            return None

        # ---- 以下均为需要应答的请求 ----
        if method == "initialize":
            return self._handle_initialize(req_id, params)
        if method == "ping":
            return MCPProtocol.success_response(req_id, {})
        if method == "tools/list":
            return self._handle_tools_list(req_id)
        if method == "tools/call":
            return self._handle_tools_call(req_id, params)
        if method == "resources/list":
            # 未声明 resources 能力，但宽容返回空列表，兼容不检查 capabilities 的客户端
            return MCPProtocol.success_response(req_id, {"resources": []})
        if method == "prompts/list":
            # 同上：宽容返回空 prompts 列表
            return MCPProtocol.success_response(req_id, {"prompts": []})
        if method == "logging/setLevel":
            # 宽容接受日志级别设置（日志走 stderr，不影响协议流）
            return MCPProtocol.success_response(req_id, {})

        return MCPProtocol.error_response(req_id, -32601, f"Unknown method: {method}")

    def _handle_initialize(self, req_id: Any, params: Dict) -> Dict:
        """
        处理 initialize 请求，进行 MCP 协议版本协商。

        规范要求：客户端请求的版本受支持则原样回显，否则返回服务端支持的版本。
        """
        requested = params.get("protocolVersion")
        if isinstance(requested, str) and requested in SUPPORTED_PROTOCOL_VERSIONS:
            version = requested
        else:
            version = MCP_PROTOCOL_VERSION
        return MCPProtocol.success_response(req_id, {
            "protocolVersion": version,
            "serverInfo": {"name": self.name, "version": self.version},
            "capabilities": {"tools": {}},
            "instructions": SERVER_INSTRUCTIONS,
        })

    def _handle_tools_list(self, req_id: Any) -> Dict:
        """
        处理 tools/list 请求。

        MCP 规范要求每个工具必须包含 inputSchema（object 类型的 JSON Schema），
        否则客户端会拒绝加载全部工具。
        """
        tools = []
        for name, func in self._tools.items():
            description = (func.__doc__ or "").strip().split('\n')[0] or name
            tools.append({
                "name": name,
                "description": description,
                "inputSchema": build_input_schema(func),
            })
        return MCPProtocol.success_response(req_id, {"tools": tools})

    def _handle_tools_call(self, req_id: Any, params: Dict) -> Dict:
        """
        处理 tools/call 请求。

        按 MCP 规范区分两类错误：
        - 未知工具/参数不合法：返回 JSON-RPC 协议错误（-32602 Invalid params）；
        - 工具执行失败：返回带 isError: true 的正常结果，便于 LLM 感知失败原因。
        """
        tool_name = params.get("name")
        if not isinstance(tool_name, str) or not tool_name:
            return MCPProtocol.error_response(req_id, -32602, "Invalid params: missing tool 'name'")
        if tool_name not in self._tools:
            return MCPProtocol.error_response(req_id, -32602, f"Unknown tool: {tool_name}")

        tool_args = params.get("arguments")
        if not isinstance(tool_args, dict):
            tool_args = {}

        try:
            result = self._tools[tool_name](**tool_args)
        except TypeError as e:
            # 参数与工具签名不匹配 -> 协议层参数错误
            logger.warning(f"Tool {tool_name} received invalid arguments: {e}")
            return MCPProtocol.error_response(req_id, -32602, f"Invalid arguments for tool '{tool_name}': {e}")
        except Exception as e:
            # 工具执行错误：按规范以 isError 结果返回，而不是 JSON-RPC 错误
            logger.exception(f"Tool {tool_name} failed")
            return MCPProtocol.success_response(req_id, {
                "content": [{"type": "text", "text": f"Tool execution failed: {e}"}],
                "isError": True,
            })

        return MCPProtocol.success_response(req_id, {
            "content": [{"type": "text", "text": json.dumps(result, default=str)}]
        })

    def run_server(self):
        """Run MCP server loop (stdio transport)."""
        # Windows 下 stdin/stdout 默认编码为 GBK，强制切换为 UTF-8 保证协议流正确
        MCPProtocol.configure_streams()
        logger.info(f"Starting {self.name} v{self.version}")

        while True:
            try:
                request = MCPProtocol.read_message()
                if request is None:
                    break  # EOF：客户端已断开

                # JSON-RPC 2.0 批量消息兼容：逐条处理，仅当存在应答时回写数组
                if isinstance(request, list):
                    responses = []
                    for item in request:
                        if not isinstance(item, dict):
                            logger.warning(f"Ignoring non-object batch item: {item!r}")
                            continue
                        response = self.handle_request(item)
                        if response is not None:
                            responses.append(response)
                    if responses:
                        MCPProtocol.write_message(responses)
                    continue

                if not isinstance(request, dict):
                    logger.warning(f"Ignoring non-object message: {request!r}")
                    continue

                # 通知返回 None：不写任何应答
                response = self.handle_request(request)
                if response is not None:
                    MCPProtocol.write_message(response)

            except KeyboardInterrupt:
                break
            except BrokenPipeError:
                logger.info("Client closed the connection")
                break
            except Exception as e:
                logger.error(f"Server error: {e}")
    
    # =========================================================================
    # STANDARD MCP TOOLS
    # =========================================================================
    
    def list_capabilities(self) -> Dict[str, Any]:
        """List all tools provided by this MCP."""
        return {
            "mcp_name": self.name,
            "version": self.version,
            "description": "Enterprise PCAP analysis with attack detection and reporting",
            "tool_count": len(self._tools),
            "categories": {
                "core_analysis": 10,
                "reconnaissance": 8,
                "http_analysis": 10,
                "attack_timeline": 6,
                "c2_detection": 6,
                "ioc_enrichment": 8,
                "protocol_analysis": 7,
                "reporting": 5
            },
            "dependencies": {
                "scapy": SCAPY_AVAILABLE,
                "pandas": PANDAS_AVAILABLE,
                "jinja2": JINJA_AVAILABLE,
                "requests": REQUESTS_AVAILABLE
            }
        }
    
    def get_documentation(self, topic: str = "general") -> Dict[str, Any]:
        """Get usage documentation for the MCP."""
        return {
            "mcp": self.name,
            "topic": topic,
            "quick_start": """
1. Load PCAP: load_pcap("/path/to/capture.pcap")
2. Get summary: get_summary()
3. Detect attacks: detect_web_exploits(), detect_port_scan()
4. Build timeline: build_attack_timeline()
5. Generate report: generate_html_report("report.html")
""",
            "supported_detections": list(self.exploit_patterns.get("patterns", {}).keys())
        }
    
    def check_installation(self) -> Dict[str, Any]:
        """Check if dependencies are installed and ready."""
        return {
            "mcp": self.name,
            "ready": SCAPY_AVAILABLE,
            "dependencies": {
                "scapy": {"installed": SCAPY_AVAILABLE, "required": True},
                "pandas": {"installed": PANDAS_AVAILABLE, "required": False},
                "jinja2": {"installed": JINJA_AVAILABLE, "required": False},
                "requests": {"installed": REQUESTS_AVAILABLE, "required": False}
            },
            "install_command": "pip install scapy pandas jinja2 requests"
        }
    
    # =========================================================================
    # HELPER METHODS
    # =========================================================================
    
    def _check_loaded(self) -> bool:
        """Check if PCAP is loaded."""
        return self.packets is not None and len(self.packets) > 0
    
    def _require_loaded(self) -> Optional[Dict]:
        """Return error dict if no PCAP loaded."""
        if not self._check_loaded():
            return {"error": "No PCAP loaded. Use load_pcap() first."}
        return None
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP address is private."""
        return any(ip.startswith(p) for p in PRIVATE_IP_PREFIXES)
    
    # =========================================================================
    # CORE ANALYSIS (10 tools)
    # =========================================================================
    
    def load_pcap(self, pcap_path: str) -> Dict[str, Any]:
        """Load PCAP file and return summary statistics."""
        if not SCAPY_AVAILABLE:
            return {"error": "scapy not installed", "install": "pip install scapy"}
        
        path = Path(pcap_path)
        if not path.exists():
            return {"error": f"File not found: {pcap_path}"}
        
        try:
            self.packets = rdpcap(str(path))
            self.pcap_path = path
            
            timestamps = [float(p.time) for p in self.packets if hasattr(p, 'time')]
            
            self.pcap_metadata = {
                "filename": path.name,
                "path": str(path),
                "size_bytes": path.stat().st_size,
                "size_mb": round(path.stat().st_size / 1024 / 1024, 2),
                "total_packets": len(self.packets),
                "first_packet": datetime.fromtimestamp(min(timestamps)).isoformat() if timestamps else None,
                "last_packet": datetime.fromtimestamp(max(timestamps)).isoformat() if timestamps else None,
                "duration_seconds": round(max(timestamps) - min(timestamps), 2) if len(timestamps) > 1 else 0
            }
            
            self._cache = {}
            
            return {"success": True, "metadata": self.pcap_metadata}
            
        except Exception as e:
            return {"error": str(e)}
    
    def get_summary(self) -> Dict[str, Any]:
        """Get high-level overview of loaded PCAP."""
        if err := self._require_loaded():
            return err
        
        src_ips, dst_ips = set(), set()
        protocols = defaultdict(int)
        
        for pkt in self.packets:
            if IP in pkt:
                src_ips.add(pkt[IP].src)
                dst_ips.add(pkt[IP].dst)
            if TCP in pkt:
                protocols["TCP"] += 1
            if UDP in pkt:
                protocols["UDP"] += 1
            if ICMP in pkt:
                protocols["ICMP"] += 1
            if DNS in pkt:
                protocols["DNS"] += 1
        
        return {
            **self.pcap_metadata,
            "unique_ips": len(src_ips | dst_ips),
            "protocols": dict(protocols)
        }
    
    def get_conversations(self, limit: int = 20) -> Dict[str, Any]:
        """Get top IP conversations by packet count."""
        if err := self._require_loaded():
            return err
        
        convs = defaultdict(lambda: {"packets": 0, "bytes": 0})
        for pkt in self.packets:
            if IP in pkt:
                key = tuple(sorted([pkt[IP].src, pkt[IP].dst]))
                convs[key]["packets"] += 1
                convs[key]["bytes"] += len(pkt)
        
        sorted_convs = sorted(convs.items(), key=lambda x: x[1]["packets"], reverse=True)[:limit]
        return {"conversations": [{"ip_a": k[0], "ip_b": k[1], **v} for k, v in sorted_convs]}
    
    def get_protocols(self) -> Dict[str, Any]:
        """Get protocol distribution breakdown."""
        if err := self._require_loaded():
            return err
        
        protocols = defaultdict(int)
        for pkt in self.packets:
            if TCP in pkt:
                protocols["TCP"] += 1
                dport = pkt[TCP].dport
                if dport in [80, 8080]:
                    protocols["HTTP"] += 1
                elif dport == 443:
                    protocols["HTTPS"] += 1
                elif dport == 22:
                    protocols["SSH"] += 1
                elif dport in [445, 139]:
                    protocols["SMB"] += 1
            elif UDP in pkt:
                protocols["UDP"] += 1
                if DNS in pkt:
                    protocols["DNS"] += 1
            elif ICMP in pkt:
                protocols["ICMP"] += 1
        
        return {"protocols": dict(protocols)}
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get deep statistics on packet sizes and timing."""
        if err := self._require_loaded():
            return err
        
        sizes = [len(pkt) for pkt in self.packets]
        return {
            "packet_sizes": {
                "min": min(sizes),
                "max": max(sizes),
                "avg": round(sum(sizes) / len(sizes), 2),
                "total": sum(sizes)
            }
        }
    
    def filter_packets(self, ip: str = None, port: int = None, protocol: str = None) -> Dict[str, Any]:
        """Filter packets by IP, port, or protocol."""
        if err := self._require_loaded():
            return err
        
        count = 0
        for pkt in self.packets:
            match = True
            if ip and IP in pkt and pkt[IP].src != ip and pkt[IP].dst != ip:
                match = False
            if port:
                ports = set()
                if TCP in pkt:
                    ports.update([pkt[TCP].sport, pkt[TCP].dport])
                if UDP in pkt:
                    ports.update([pkt[UDP].sport, pkt[UDP].dport])
                if port not in ports:
                    match = False
            if match:
                count += 1
        
        return {"original": len(self.packets), "filtered": count}
    
    def export_packets(self, output_path: str, **filters) -> Dict[str, Any]:
        """Export filtered packets to new PCAP file."""
        if err := self._require_loaded():
            return err
        
        try:
            wrpcap(output_path, self.packets)
            return {"success": True, "path": output_path}
        except Exception as e:
            return {"error": str(e)}
    
    def get_packet_details(self, index: int) -> Dict[str, Any]:
        """Get full packet details by index."""
        if err := self._require_loaded():
            return err
        if index < 0 or index >= len(self.packets):
            return {"error": f"Invalid index: {index}"}
        
        pkt = self.packets[index]
        details = {"index": index, "length": len(pkt), "layers": []}
        if IP in pkt:
            details["layers"].append({"layer": "IP", "src": pkt[IP].src, "dst": pkt[IP].dst})
        if TCP in pkt:
            details["layers"].append({"layer": "TCP", "sport": pkt[TCP].sport, "dport": pkt[TCP].dport})
        if Raw in pkt:
            details["payload_preview"] = bytes(pkt[Raw].load)[:100].hex()
        return details
    
    def search_payload(self, pattern: str, limit: int = 100) -> Dict[str, Any]:
        """Search payloads for regex pattern."""
        if err := self._require_loaded():
            return err
        
        matches = []
        regex = re.compile(pattern.encode(), re.IGNORECASE)
        for i, pkt in enumerate(self.packets):
            if Raw in pkt and regex.search(bytes(pkt[Raw].load)):
                matches.append({"index": i, "src": pkt[IP].src if IP in pkt else None})
                if len(matches) >= limit:
                    break
        
        return {"pattern": pattern, "matches": len(matches), "results": matches}
    
    def get_unique_values(self, value_type: str = "all") -> Dict[str, Any]:
        """Extract unique IPs, ports, or domains from PCAP."""
        if err := self._require_loaded():
            return err

        # 参数别名归一化：ip/ips、port/ports、domain/domains 均可；
        # 非法取值直接报错而不是静默返回空结果
        normalized = value_type.strip().lower()
        if normalized not in ("all", "ip", "ips", "port", "ports", "domain", "domains"):
            return {
                "error": (
                    f"Invalid value_type: '{value_type}'. "
                    "Valid values: all, ips, ports, domains"
                )
            }

        result = {}
        if normalized in ("all", "ip", "ips"):
            ips = set()
            for pkt in self.packets:
                if IP in pkt:
                    ips.update([pkt[IP].src, pkt[IP].dst])
            result["ips"] = sorted(list(ips))

        if normalized in ("all", "port", "ports"):
            # 端口取值：收集 TCP/UDP 的源端口与目的端口
            ports = set()
            for pkt in self.packets:
                if TCP in pkt:
                    ports.update([pkt[TCP].sport, pkt[TCP].dport])
                elif UDP in pkt:
                    ports.update([pkt[UDP].sport, pkt[UDP].dport])
            result["ports"] = sorted(list(ports))

        if normalized in ("all", "domain", "domains"):
            domains = set()
            for pkt in self.packets:
                if DNS in pkt and DNSQR in pkt:
                    q = pkt[DNSQR].qname
                    domains.add((q.decode() if isinstance(q, bytes) else q).rstrip('.'))
            result["domains"] = sorted(list(domains))

        return result
    
    # =========================================================================
    # RECONNAISSANCE (8 tools)
    # =========================================================================
    
    def detect_port_scan(self, threshold: int = DEFAULT_PORT_SCAN_THRESHOLD) -> Dict[str, Any]:
        """Detect port scanning activity based on SYN packet patterns."""
        if err := self._require_loaded():
            return err
        
        syn_by_src = defaultdict(lambda: {"ports": set(), "targets": set()})
        for pkt in self.packets:
            if TCP in pkt and IP in pkt:
                # SYN flag set, ACK not set
                if pkt[TCP].flags & 0x02 and not (pkt[TCP].flags & 0x10):
                    src = pkt[IP].src
                    syn_by_src[src]["ports"].add(pkt[TCP].dport)
                    syn_by_src[src]["targets"].add(pkt[IP].dst)
        
        scanners = []
        for ip, data in syn_by_src.items():
            if len(data["ports"]) >= threshold:
                scanners.append({
                    "scanner_ip": ip,
                    "ports_scanned": len(data["ports"]),
                    "targets": list(data["targets"]),
                    "confidence": min(100, len(data["ports"]) * 5)
                })
        
        return {"scan_detected": len(scanners) > 0, "scanners": scanners}
    
    def get_open_ports(self) -> Dict[str, Any]:
        """List open ports inferred from SYN-ACK responses."""
        if err := self._require_loaded():
            return err
        
        open_ports = defaultdict(set)
        for pkt in self.packets:
            if TCP in pkt and IP in pkt and (pkt[TCP].flags & 0x12 == 0x12):
                open_ports[pkt[IP].src].add(pkt[TCP].sport)
        
        return {"results": [{"ip": ip, "ports": sorted(list(ports))} for ip, ports in open_ports.items()]}
    
    def detect_host_discovery(self) -> Dict[str, Any]:
        """Find ICMP ping sweeps or ARP scans."""
        if err := self._require_loaded():
            return err
        
        icmp_by_src = defaultdict(set)
        for pkt in self.packets:
            if ICMP in pkt and IP in pkt and pkt[ICMP].type == 8:  # Echo request
                icmp_by_src[pkt[IP].src].add(pkt[IP].dst)
        
        sweeps = [{"src": src, "targets": len(targets)} for src, targets in icmp_by_src.items() if len(targets) >= 3]
        return {"sweeps": sweeps}
    
    def detect_service_scan(self) -> Dict[str, Any]:
        """Identify service enumeration attempts (data sent after connection)."""
        if err := self._require_loaded():
            return err
        
        probes = defaultdict(set)
        for pkt in self.packets:
            if TCP in pkt and IP in pkt and Raw in pkt and (pkt[TCP].flags & 0x18):  # PSH+ACK
                probes[pkt[IP].src].add(pkt[TCP].dport)
        
        scanners = [{"ip": ip, "ports": len(ports)} for ip, ports in probes.items() if len(ports) >= 5]
        return {"scanners": scanners}
    
    def get_first_responder(self) -> Dict[str, Any]:
        """Find first port to respond with SYN-ACK."""
        if err := self._require_loaded():
            return err
        
        for pkt in self.packets:
            if TCP in pkt and IP in pkt and (pkt[TCP].flags & 0x12 == 0x12):
                return {"ip": pkt[IP].src, "port": pkt[TCP].sport}
        return {"first_responder": None}
    
    def analyze_scan_pattern(self) -> Dict[str, Any]:
        """Characterize scan type (SYN, FIN, XMAS, etc.)."""
        if err := self._require_loaded():
            return err
        
        patterns = {"syn_only": 0, "fin_scan": 0, "xmas_scan": 0}
        for pkt in self.packets:
            if TCP in pkt:
                f = pkt[TCP].flags
                if f == 0x02:
                    patterns["syn_only"] += 1
                elif f == 0x01:
                    patterns["fin_scan"] += 1
                elif f == 0x29:
                    patterns["xmas_scan"] += 1
        
        return {"patterns": patterns, "dominant": max(patterns, key=patterns.get)}
    
    def identify_scanner(self) -> Dict[str, Any]:
        """Identify likely attacker/scanner IP."""
        scan = self.detect_port_scan(threshold=10)
        if scan.get("scanners"):
            return {"scanner": scan["scanners"][0]["scanner_ip"]}
        return {"scanner": None}
    
    def get_scan_summary(self) -> Dict[str, Any]:
        """Get complete reconnaissance summary."""
        return {
            "port_scan": self.detect_port_scan(),
            "host_discovery": self.detect_host_discovery(),
            "scan_pattern": self.analyze_scan_pattern()
        }
    
    # =========================================================================
    # HTTP/WEB (10 tools)
    # =========================================================================
    
    def extract_http_requests(self) -> Dict[str, Any]:
        """Extract all HTTP requests from PCAP."""
        if err := self._require_loaded():
            return err
        
        requests_found = []
        for i, pkt in enumerate(self.packets):
            if TCP in pkt and Raw in pkt:
                payload = bytes(pkt[Raw].load)
                if any(payload.startswith(m) for m in [b'GET ', b'POST ', b'PUT ', b'HEAD ', b'DELETE ']):
                    try:
                        decoded = payload.decode('utf-8', errors='replace')
                        lines = decoded.split('\r\n')
                        parts = lines[0].split(' ')
                        requests_found.append({
                            "index": i,
                            "method": parts[0],
                            "uri": parts[1] if len(parts) > 1 else "",
                            "src": pkt[IP].src if IP in pkt else None
                        })
                    except Exception:
                        pass
        
        return {"count": len(requests_found), "requests": requests_found}
    
    def extract_http_responses(self) -> Dict[str, Any]:
        """Extract all HTTP responses from PCAP."""
        if err := self._require_loaded():
            return err
        
        responses = []
        for i, pkt in enumerate(self.packets):
            if TCP in pkt and Raw in pkt:
                payload = bytes(pkt[Raw].load)
                if payload.startswith(b'HTTP/'):
                    try:
                        status = payload.decode('utf-8', errors='replace').split('\r\n')[0]
                        parts = status.split(' ', 2)
                        responses.append({
                            "index": i,
                            "status_code": int(parts[1]) if len(parts) > 1 else 0,
                            "src": pkt[IP].src if IP in pkt else None
                        })
                    except Exception:
                        pass
        
        return {"count": len(responses), "responses": responses}
    
    def get_http_sessions(self) -> Dict[str, Any]:
        """Get request-response pair count."""
        req = self.extract_http_requests()
        resp = self.extract_http_responses()
        return {"requests": req.get("count", 0), "responses": resp.get("count", 0)}
    
    def detect_web_exploits(self) -> Dict[str, Any]:
        """Detect CVE patterns and web exploits in HTTP traffic."""
        if err := self._require_loaded():
            return err
        
        findings = []
        patterns = self.exploit_patterns.get("patterns", {})
        
        for i, pkt in enumerate(self.packets):
            if Raw in pkt:
                payload = bytes(pkt[Raw].load).decode('utf-8', errors='replace')
                for vuln_id, vuln_data in patterns.items():
                    for pattern in vuln_data.get("patterns", []):
                        try:
                            if re.search(pattern, payload, re.IGNORECASE):
                                findings.append({
                                    "index": i,
                                    "vulnerability": vuln_id,
                                    "name": vuln_data.get("name", vuln_id),
                                    "severity": vuln_data.get("severity", "unknown"),
                                    "src": pkt[IP].src if IP in pkt else None,
                                    "dst": pkt[IP].dst if IP in pkt else None,
                                    "mitre": vuln_data.get("mitre_techniques", [])
                                })
                                break
                        except Exception:
                            pass
        
        unique = {(f["vulnerability"], f["src"]): f for f in findings}
        return {"exploits_detected": len(unique), "findings": list(unique.values())}
    
    def extract_post_payloads(self) -> Dict[str, Any]:
        """Extract POST request bodies."""
        if err := self._require_loaded():
            return err
        
        posts = []
        for i, pkt in enumerate(self.packets):
            if TCP in pkt and Raw in pkt:
                payload = bytes(pkt[Raw].load)
                if payload.startswith(b'POST '):
                    parts = payload.decode('utf-8', errors='replace').split('\r\n\r\n', 1)
                    posts.append({"index": i, "body": parts[1][:500] if len(parts) > 1 else ""})
        
        return {"count": len(posts), "posts": posts}
    
    def extract_server_info(self) -> Dict[str, Any]:
        """Extract server headers from HTTP responses."""
        if err := self._require_loaded():
            return err
        
        servers = {}
        for pkt in self.packets:
            if TCP in pkt and Raw in pkt and IP in pkt:
                payload = bytes(pkt[Raw].load).decode('utf-8', errors='replace')
                for line in payload.split('\r\n'):
                    if line.lower().startswith('server:'):
                        servers[pkt[IP].src] = line.split(':', 1)[1].strip()
        
        return {"servers": servers}
    
    def find_file_transfers(self) -> Dict[str, Any]:
        """Detect file transfers by magic bytes."""
        if err := self._require_loaded():
            return err
        
        sigs = {b'%PDF': 'PDF', b'PK': 'ZIP', b'\x89PNG': 'PNG', b'MZ': 'EXE'}
        transfers = []
        for i, pkt in enumerate(self.packets):
            if Raw in pkt:
                payload = bytes(pkt[Raw].load)
                for sig, ftype in sigs.items():
                    if sig in payload[:100]:
                        transfers.append({"index": i, "type": ftype})
                        break
        
        return {"transfers": transfers}
    
    def detect_webshells(self) -> Dict[str, Any]:
        """Detect webshell indicators (Godzilla, China Chopper, classic PHP shells)."""
        if err := self._require_loaded():
            return err

        # WebShell 家族特征集：经典 PHP 一句话、命令执行函数、
        # 哥斯拉（pass=/key=）、中国菜刀（cmd/z0）等管理端常用参数
        signatures = {
            "classic_eval": rb'eval\s*\(\s*(?:base64_decode\s*\(\s*)?\$_(?:POST|GET|REQUEST|COOKIE)',
            "classic_assert": rb'assert\s*\(\s*\$_(?:POST|GET|REQUEST|COOKIE)',
            "shell_names": rb'\b(?:c99|r57|wso|b374k|cmd\.php)\b',
            "cmd_exec": rb'(?:shell_exec|passthru|proc_open|popen|system)\s*\(',
            "godzilla_params": rb'(?:^|[\s?&])(?:pass|key)=',
            "chopper_params": rb'(?:^|[\s?&])(?:cmd|command|z0|z1)=',
        }
        compiled = {name: re.compile(p, re.IGNORECASE | re.MULTILINE)
                    for name, p in signatures.items()}

        sig_counts = {name: 0 for name in signatures}
        results = []
        for i, pkt in enumerate(self.packets):
            if Raw not in pkt:
                continue
            payload = bytes(pkt[Raw].load)
            for name, regex in compiled.items():
                m = regex.search(payload)
                if m:
                    sig_counts[name] += 1
                    # 保留命中点前后各 40 字节的上下文片段，便于人工研判
                    start = max(0, m.start() - 40)
                    snippet = payload[start:m.end() + 40].decode('utf-8', errors='replace')
                    results.append({
                        "index": i,
                        "src": pkt[IP].src if IP in pkt else None,
                        "dst": pkt[IP].dst if IP in pkt else None,
                        "signature": name,
                        "match": m.group(0).decode('utf-8', errors='replace'),
                        "snippet": snippet,
                    })

        # 结构性启发：同一 .php 端点被反复 POST，是哥斯拉/冰蝎等
        # 加密 WebShell 的典型行为特征（无明文特征可匹配时的兜底检测）
        post_counts = defaultdict(int)
        for pkt in self.packets:
            if TCP in pkt and Raw in pkt:
                payload = bytes(pkt[Raw].load)
                if payload.startswith(b'POST '):
                    try:
                        uri = payload.split(b' ', 2)[1].decode('utf-8', errors='replace')
                        path = uri.split('?')[0]
                        if path.endswith('.php'):
                            post_counts[path] += 1
                    except (IndexError, ValueError):
                        continue
        suspicious_endpoints = [
            {"uri": uri, "post_count": count}
            for uri, count in sorted(post_counts.items(), key=lambda x: -x[1])
            if count >= DEFAULT_WEBSHELL_POST_THRESHOLD
        ]

        webshell_suspected = any(v > 0 for v in sig_counts.values()) or bool(suspicious_endpoints)
        return {
            "webshell_suspected": webshell_suspected,
            "signatures_matched": {k: v for k, v in sig_counts.items() if v > 0},
            "matches": len(results),
            "results": results[:50],
            "suspicious_endpoints": suspicious_endpoints[:20],
        }
    
    def get_user_agents(self) -> Dict[str, Any]:
        """Get unique User-Agent strings."""
        if err := self._require_loaded():
            return err
        
        uas = defaultdict(int)
        for pkt in self.packets:
            if Raw in pkt:
                payload = bytes(pkt[Raw].load).decode('utf-8', errors='replace')
                m = re.search(r'User-Agent:\s*([^\r\n]+)', payload)
                if m:
                    uas[m.group(1)] += 1
        
        return {"user_agents": [{"ua": ua, "count": c} for ua, c in sorted(uas.items(), key=lambda x: x[1], reverse=True)]}
    
    def analyze_http_timeline(self) -> Dict[str, Any]:
        """Get HTTP activity timeline."""
        return self.extract_http_requests()
    
    # =========================================================================
    # ATTACK TIMELINE (6 tools)
    # =========================================================================
    
    def build_attack_timeline(self) -> Dict[str, Any]:
        """Build complete attack timeline with phases."""
        if err := self._require_loaded():
            return err
        
        events = []
        
        # Reconnaissance phase
        scans = self.detect_port_scan(threshold=10)
        for s in scans.get("scanners", []):
            events.append({
                "phase": "Reconnaissance",
                "type": "Port Scan",
                "source": s["scanner_ip"],
                "severity": "medium"
            })
        
        # Initial Access phase
        exploits = self.detect_web_exploits()
        for f in exploits.get("findings", []):
            events.append({
                "phase": "Initial Access",
                "type": f["name"],
                "source": f["src"],
                "severity": f["severity"],
                "mitre": f.get("mitre", [])
            })
        
        # Execution phase
        shells = self.detect_reverse_shells()
        for s in shells.get("shells", []):
            events.append({
                "phase": "Execution",
                "type": "Reverse Shell",
                "source": s.get("src"),
                "severity": "critical"
            })
        
        return {"events": events, "phases": list(set(e["phase"] for e in events))}
    
    def identify_attack_phases(self) -> Dict[str, Any]:
        """Map events to Cyber Kill Chain phases."""
        timeline = self.build_attack_timeline()
        phases = defaultdict(list)
        for e in timeline.get("events", []):
            phases[e["phase"]].append(e)
        return {"kill_chain": [{"phase": k, "count": len(v)} for k, v in phases.items()]}
    
    def find_initial_access(self) -> Dict[str, Any]:
        """Find initial exploitation event."""
        exploits = self.detect_web_exploits()
        findings = exploits.get("findings", [])
        return {"found": len(findings) > 0, "first": findings[0] if findings else None}
    
    def find_initial_foothold(self) -> Dict[str, Any]:
        """Find persistence establishment indicators."""
        return self.detect_webshells()
    
    def detect_lateral_movement(self) -> Dict[str, Any]:
        """Detect internal lateral movement attempts."""
        if err := self._require_loaded():
            return err
        
        lateral = []
        for pkt in self.packets:
            if TCP in pkt and IP in pkt:
                src, dst = pkt[IP].src, pkt[IP].dst
                if self._is_private_ip(src) and self._is_private_ip(dst):
                    if pkt[TCP].dport in [445, 3389, 22, 5985]:
                        lateral.append({"src": src, "dst": dst, "port": pkt[TCP].dport})
        
        unique = {(l["src"], l["dst"], l["port"]): l for l in lateral}
        return {"lateral_movement": list(unique.values())}
    
    def map_to_mitre(self) -> Dict[str, Any]:
        """Map detected activity to MITRE ATT&CK techniques."""
        timeline = self.build_attack_timeline()
        techniques = {}
        for e in timeline.get("events", []):
            for t in e.get("mitre", []):
                if t not in techniques:
                    info = self.mitre_mapping.get("techniques", {}).get(t, {})
                    techniques[t] = {
                        "id": t,
                        "name": info.get("name", t),
                        "tactic": info.get("tactic", "")
                    }
        return {"techniques": list(techniques.values())}
    
    # =========================================================================
    # C2 DETECTION (6 tools)
    # =========================================================================
    
    def detect_reverse_shells(self) -> Dict[str, Any]:
        """Detect reverse shell patterns in traffic."""
        if err := self._require_loaded():
            return err
        
        shells = []
        patterns = self.c2_indicators.get("reverse_shell_patterns", {})
        
        for i, pkt in enumerate(self.packets):
            if Raw in pkt:
                payload = bytes(pkt[Raw].load).decode('utf-8', errors='replace')
                for shell_type, data in patterns.items():
                    for p in data.get("patterns", []):
                        if re.search(p, payload, re.IGNORECASE):
                            shells.append({
                                "index": i,
                                "type": data.get("name"),
                                "src": pkt[IP].src if IP in pkt else None
                            })
                            break
        
        return {"shells": shells}
    
    def analyze_shell_traffic(self) -> Dict[str, Any]:
        """Extract shell commands from traffic."""
        if err := self._require_loaded():
            return err
        
        commands = []
        cmd_patterns = self.c2_indicators.get("shell_command_patterns", {})
        
        for i, pkt in enumerate(self.packets):
            if Raw in pkt:
                payload = bytes(pkt[Raw].load).decode('utf-8', errors='replace')
                for cat, data in cmd_patterns.items():
                    for p in data.get("patterns", []):
                        if re.search(p, payload, re.IGNORECASE):
                            commands.append({"index": i, "category": cat, "pattern": p})
        
        return {"commands": commands}
    
    def detect_c2_beacons(self, interval_threshold: float = DEFAULT_BEACON_INTERVAL_THRESHOLD) -> Dict[str, Any]:
        """Detect periodic C2 beacon check-ins."""
        if err := self._require_loaded():
            return err
        
        conns = defaultdict(list)
        for pkt in self.packets:
            if TCP in pkt and IP in pkt and (pkt[TCP].flags & 0x02):  # SYN
                conns[(pkt[IP].src, pkt[IP].dst, pkt[TCP].dport)].append(float(pkt.time))
        
        beacons = []
        for key, times in conns.items():
            if len(times) >= 5:
                intervals = [times[i + 1] - times[i] for i in range(len(times) - 1)]
                avg = sum(intervals) / len(intervals)
                var = sum((i - avg) ** 2 for i in intervals) / len(intervals)
                # Low variance indicates regular interval (beaconing)
                if var < (avg * 0.3) ** 2:
                    beacons.append({
                        "src": key[0],
                        "dst": key[1],
                        "port": key[2],
                        "interval": round(avg, 2)
                    })
        
        return {"beacons": beacons}
    
    def detect_data_exfil(self, threshold_bytes: int = DEFAULT_EXFIL_BYTES_THRESHOLD) -> Dict[str, Any]:
        """Detect large outbound data transfers."""
        if err := self._require_loaded():
            return err
        
        outbound = defaultdict(int)
        for pkt in self.packets:
            if IP in pkt and Raw in pkt:
                outbound[pkt[IP].dst] += len(pkt[Raw].load)
        
        large = [{"dst": dst, "bytes": b} for dst, b in outbound.items() if b >= threshold_bytes]
        return {"large_transfers": sorted(large, key=lambda x: x["bytes"], reverse=True)}
    
    def identify_c2_channels(self) -> Dict[str, Any]:
        """Characterize C2 communication channels."""
        beacons = self.detect_c2_beacons()
        shells = self.detect_reverse_shells()
        return {
            "beacon_count": len(beacons.get("beacons", [])),
            "shell_count": len(shells.get("shells", []))
        }
    
    def extract_shell_commands(self) -> Dict[str, Any]:
        """Parse and extract shell commands from traffic."""
        return self.analyze_shell_traffic()
    
    # =========================================================================
    # IOC ENRICHMENT (8 tools)
    # =========================================================================
    
    def extract_all_iocs(self) -> Dict[str, Any]:
        """Extract all Indicators of Compromise from PCAP."""
        unique = self.get_unique_values("all")
        return {"ips": unique.get("ips", []), "domains": unique.get("domains", [])}
    
    def enrich_ip(self, ip: str) -> Dict[str, Any]:
        """Get basic IP enrichment (private/public classification)."""
        is_private = self._is_private_ip(ip)
        return {"ip": ip, "is_private": is_private, "type": "private" if is_private else "public"}
    
    def check_virustotal(self, ioc: str, api_key: str = None) -> Dict[str, Any]:
        """Query VirusTotal for IP/domain reputation."""
        api_key = api_key or os.environ.get("VIRUSTOTAL_API_KEY")
        if not api_key:
            return {"error": "API key required"}
        
        if not REQUESTS_AVAILABLE:
            return {"error": "requests not installed"}
        
        try:
            headers = {"x-apikey": api_key}
            r = requests.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}",
                headers=headers,
                timeout=10
            )
            return r.json() if r.status_code == 200 else {"error": f"API error: {r.status_code}"}
        except Exception as e:
            return {"error": str(e)}
    
    def check_abuseipdb(self, ip: str, api_key: str = None) -> Dict[str, Any]:
        """Query AbuseIPDB for IP reputation."""
        api_key = api_key or os.environ.get("ABUSEIPDB_API_KEY")
        if not api_key:
            return {"error": "API key required"}
        
        if not REQUESTS_AVAILABLE:
            return {"error": "requests not installed"}
        
        try:
            headers = {"Key": api_key, "Accept": "application/json"}
            r = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers=headers,
                params={"ipAddress": ip},
                timeout=10
            )
            return r.json() if r.status_code == 200 else {"error": f"API error: {r.status_code}"}
        except Exception as e:
            return {"error": str(e)}
    
    def check_otx(self, ioc: str) -> Dict[str, Any]:
        """Query AlienVault OTX (requires API key)."""
        return {"status": "requires_api_key", "ioc": ioc}
    
    def defang_iocs(self) -> Dict[str, Any]:
        """Defang IoCs for safe sharing."""
        iocs = self.extract_all_iocs()
        return {
            "ips": [ip.replace('.', '[.]') for ip in iocs.get("ips", [])],
            "domains": [d.replace('.', '[.]') for d in iocs.get("domains", [])]
        }
    
    def export_iocs_stix(self) -> Dict[str, Any]:
        """Export IoCs in STIX 2.0 format."""
        iocs = self.extract_all_iocs()
        stix_objects = []
        for ip in iocs.get("ips", []):
            stix_objects.append({
                "type": "indicator",
                "pattern": f"[ipv4-addr:value = '{ip}']",
                "pattern_type": "stix"
            })
        return {"stix_objects": stix_objects}
    
    def get_threat_context(self) -> Dict[str, Any]:
        """Get combined threat intelligence summary."""
        iocs = self.extract_all_iocs()
        exploits = self.detect_web_exploits()
        return {
            "ioc_count": len(iocs.get("ips", [])) + len(iocs.get("domains", [])),
            "exploits_detected": exploits.get("exploits_detected", 0),
            "severity": "critical" if exploits.get("exploits_detected", 0) > 0 else "info"
        }
    
    # =========================================================================
    # PROTOCOL ANALYSIS (7 tools)
    # =========================================================================
    
    def analyze_dns(self) -> Dict[str, Any]:
        """Analyze DNS traffic for queries and tunneling indicators."""
        if err := self._require_loaded():
            return err
        
        queries = []
        for pkt in self.packets:
            if DNS in pkt and DNSQR in pkt:
                q = pkt[DNSQR].qname
                queries.append({
                    "query": (q.decode() if isinstance(q, bytes) else q).rstrip('.'),
                    "src": pkt[IP].src if IP in pkt else None
                })
        
        suspicious = [q for q in queries if len(q["query"]) > 50]
        return {"queries": len(queries), "suspicious_tunneling": suspicious}
    
    def analyze_smb(self) -> Dict[str, Any]:
        """Analyze SMB traffic."""
        if err := self._require_loaded():
            return err
        
        smb = []
        for pkt in self.packets:
            if TCP in pkt and IP in pkt and pkt[TCP].dport in [445, 139]:
                smb.append({"src": pkt[IP].src, "dst": pkt[IP].dst})
        return {"smb_connections": len(smb)}
    
    def analyze_ftp(self) -> Dict[str, Any]:
        """Analyze FTP traffic and extract credentials."""
        if err := self._require_loaded():
            return err
        
        commands = []
        creds = []
        for pkt in self.packets:
            if TCP in pkt and Raw in pkt and (pkt[TCP].dport == 21 or pkt[TCP].sport == 21):
                payload = bytes(pkt[Raw].load).decode('utf-8', errors='replace')
                if payload.startswith('USER '):
                    creds.append({"type": "user", "value": payload[5:].strip()})
                elif payload.startswith('PASS '):
                    creds.append({"type": "pass", "value": payload[5:].strip()})
                commands.append(payload.strip()[:50])
        return {"commands": len(commands), "credentials": creds}
    
    def analyze_ssh(self) -> Dict[str, Any]:
        """Analyze SSH traffic sessions."""
        if err := self._require_loaded():
            return err
        
        sessions = defaultdict(int)
        for pkt in self.packets:
            if TCP in pkt and IP in pkt and (pkt[TCP].dport == 22 or pkt[TCP].sport == 22):
                sessions[(pkt[IP].src, pkt[IP].dst)] += 1
        return {"sessions": len(sessions)}
    
    def analyze_rdp(self) -> Dict[str, Any]:
        """Analyze RDP connection attempts."""
        if err := self._require_loaded():
            return err
        
        attempts = []
        for pkt in self.packets:
            if TCP in pkt and IP in pkt and pkt[TCP].dport == 3389 and (pkt[TCP].flags & 0x02):
                attempts.append({"src": pkt[IP].src, "dst": pkt[IP].dst})
        return {"rdp_attempts": len(attempts)}
    
    def analyze_smtp(self) -> Dict[str, Any]:
        """Analyze SMTP traffic."""
        if err := self._require_loaded():
            return err
        
        count = sum(1 for pkt in self.packets if TCP in pkt and (pkt[TCP].dport == 25 or pkt[TCP].sport == 25))
        return {"smtp_packets": count}
    
    def analyze_tls(self) -> Dict[str, Any]:
        """Analyze TLS handshakes."""
        if err := self._require_loaded():
            return err
        
        handshakes = 0
        for pkt in self.packets:
            if TCP in pkt and Raw in pkt and pkt[TCP].dport == 443:
                if bytes(pkt[Raw].load)[0:1] == b'\x16':  # TLS handshake record type
                    handshakes += 1
        return {"tls_handshakes": handshakes}
    
    # =========================================================================
    # REPORTING (5 tools)
    # =========================================================================
    
    def generate_html_report(self, output_path: str = "pcap_report.html") -> Dict[str, Any]:
        """Generate full HTML investigation report."""
        if not JINJA_AVAILABLE:
            return {"error": "jinja2 not installed"}
        if err := self._require_loaded():
            return err
        
        try:
            template = None
            # 优先使用外部模板目录中的 report_base.html；模板缺失或加载失败时回退到内置模板
            if TEMPLATES_DIR.exists():
                try:
                    fs_env = Environment(loader=FileSystemLoader(str(TEMPLATES_DIR)))
                    template = fs_env.get_template("report_base.html")
                except Exception:
                    logger.warning("report_base.html not found or failed to load, using embedded template")
                    template = None
            if template is None:
                env = Environment(loader=BaseLoader())
                template = env.from_string(self._get_embedded_template())
            
            data = {
                "title": f"PCAP Analysis: {self.pcap_metadata.get('filename', 'Unknown')}",
                "subtitle": "Network Forensics Investigation Report",
                "generation_time": datetime.now().isoformat(),
                "summary": self.get_summary(),
                "exploits": self.detect_web_exploits(),
                "timeline": self.build_attack_timeline(),
                "iocs": self.extract_all_iocs()
            }
            
            html = template.render(**data)
            Path(output_path).write_text(html, encoding='utf-8')
            
            return {"success": True, "path": output_path}
        except Exception as e:
            return {"error": str(e)}
    
    def _get_embedded_template(self) -> str:
        """Return minimal embedded HTML template."""
        return """<!DOCTYPE html>
<html><head><title>{{ title }}</title>
<style>
body { font-family: monospace; background: #0a0f1a; color: #e2e8f0; padding: 20px; }
h1, h2 { color: #9FEF00; }
.section { background: #1a2332; padding: 20px; margin: 20px 0; border-radius: 8px; }
table { width: 100%; border-collapse: collapse; }
th, td { padding: 8px; text-align: left; border-bottom: 1px solid #2d3748; }
th { color: #9FEF00; }
.critical { color: #ef4444; }
.high { color: #f97316; }
</style></head><body>
<h1>{{ title }}</h1>
<p>{{ subtitle }} - Generated: {{ generation_time }}</p>
<div class="section"><h2>Summary</h2>
<p>Total Packets: {{ summary.total_packets }}</p>
<p>Unique IPs: {{ summary.unique_ips }}</p>
</div>
<div class="section"><h2>Exploits Detected: {{ exploits.exploits_detected }}</h2>
{% for f in exploits.findings %}
<p class="{{ f.severity }}">{{ f.name }} - {{ f.src }} -> {{ f.dst }}</p>
{% endfor %}
</div>
<div class="section"><h2>Attack Timeline</h2>
{% for e in timeline.events %}
<p>[{{ e.phase }}] {{ e.type }} - {{ e.source }}</p>
{% endfor %}
</div>
</body></html>"""
    
    def generate_executive_summary(self) -> Dict[str, Any]:
        """Generate executive summary data."""
        summary = self.get_summary()
        exploits = self.detect_web_exploits()
        return {
            "pcap": self.pcap_metadata,
            "key_findings": {
                "packets": summary.get("total_packets", 0),
                "ips": summary.get("unique_ips", 0),
                "exploits": exploits.get("exploits_detected", 0)
            },
            "severity": "critical" if exploits.get("exploits_detected", 0) > 0 else "info"
        }
    
    def _write_html_report(self, output_path: str, title: str, body_html: str) -> Dict[str, Any]:
        """将 HTML 内容写入报告文件，供 timeline / IoC 报告共用（纯 stdlib，不依赖 jinja2）。"""
        html_doc = (
            "<!DOCTYPE html>\n<html>\n<head>\n<meta charset=\"utf-8\">\n"
            f"<title>{escape_html(title)}</title>\n<style>\n"
            "body { font-family: monospace; background: #0a0f1a; color: #e2e8f0; padding: 20px; }\n"
            "h1, h2 { color: #9FEF00; }\n"
            "table { border-collapse: collapse; width: 100%; margin: 10px 0; }\n"
            "th, td { border: 1px solid #2d3a4f; padding: 6px 10px; text-align: left; }\n"
            "th { background: #1a2332; color: #9FEF00; }\n"
            ".meta { color: #7a8699; }\n"
            ".defanged { background: #1a2332; padding: 10px; border-radius: 6px; word-break: break-all; }\n"
            "</style>\n</head>\n<body>\n"
            f"<h1>{escape_html(title)}</h1>\n"
            f"<p class='meta'>PCAP: {escape_html(self.pcap_metadata.get('filename', 'Unknown'))} — "
            f"generated {datetime.now().isoformat()}</p>\n"
            f"{body_html}\n</body>\n</html>\n"
        )
        Path(output_path).write_text(html_doc, encoding='utf-8')
        return {"success": True, "path": output_path}

    def generate_timeline_html(self, output_path: str = "timeline.html") -> Dict[str, Any]:
        """Generate attack timeline HTML report file."""
        if err := self._require_loaded():
            return err

        timeline = self.build_attack_timeline()
        events = timeline.get("events", [])
        try:
            # 每个事件渲染为表格行：阶段 / 类型 / 来源 / 严重程度
            rows = [
                "<tr>"
                f"<td>{escape_html(str(e.get('phase', '')))}</td>"
                f"<td>{escape_html(str(e.get('type', '')))}</td>"
                f"<td>{escape_html(str(e.get('source') or ''))}</td>"
                f"<td>{escape_html(str(e.get('severity', 'info')))}</td>"
                "</tr>"
                for e in events
            ]
            body = (
                f"<h2>Timeline Events ({len(events)})</h2>\n"
                "<table>\n<tr><th>Phase</th><th>Type</th><th>Source</th><th>Severity</th></tr>\n"
                + "\n".join(rows)
                + "\n</table>\n"
            )
            result = self._write_html_report(output_path, "Attack Timeline Report", body)
            result.update({"total_events": len(events), "phases": timeline.get("phases", [])})
            return result
        except Exception as e:
            return {"error": str(e)}

    def generate_ioc_report(self, output_path: str = "iocs.html") -> Dict[str, Any]:
        """Generate IoC-focused HTML report file."""
        if err := self._require_loaded():
            return err

        try:
            iocs = self.extract_all_iocs()
            defanged = self.defang_iocs()
            ips = iocs.get("ips", [])
            domains = iocs.get("domains", [])
            def_ips = defanged.get("ips", [])
            def_domains = defanged.get("domains", [])

            # 渲染 IP / 域名表格与去武器化 IoC 明细
            def _rows(values):
                return "\n".join(f"<tr><td>{escape_html(str(v))}</td></tr>" for v in values)

            body = (
                f"<h2>IP Addresses ({len(ips)})</h2>\n"
                "<table>\n<tr><th>IP</th></tr>\n" + _rows(ips) + "\n</table>\n"
                f"<h2>Domains ({len(domains)})</h2>\n"
                "<table>\n<tr><th>Domain</th></tr>\n" + _rows(domains) + "\n</table>\n"
                "<h2>Defanged IoCs (safe for sharing)</h2>\n"
                f"<p class='defanged'>{escape_html(' ; '.join(def_ips + def_domains))}</p>\n"
            )
            result = self._write_html_report(output_path, "IoC Report", body)
            result.update({"total_ips": len(ips), "total_domains": len(domains)})
            return result
        except Exception as e:
            return {"error": str(e)}
    
    def export_findings_json(self, output_path: str = "findings.json") -> Dict[str, Any]:
        """Export all findings as JSON file."""
        if err := self._require_loaded():
            return err
        
        findings = {
            "metadata": self.pcap_metadata,
            "summary": self.get_summary(),
            "exploits": self.detect_web_exploits(),
            "timeline": self.build_attack_timeline(),
            "iocs": self.extract_all_iocs(),
            "mitre": self.map_to_mitre(),
            "generated": datetime.now().isoformat()
        }
        
        try:
            Path(output_path).write_text(json.dumps(findings, indent=2, default=str), encoding='utf-8')
            return {"success": True, "path": output_path}
        except Exception as e:
            return {"error": str(e)}


# -*- coding: utf-8 -*-
"""
Constants and default configurations for PCAP Analysis MCP.
"""

from pathlib import Path

# =============================================================================
# PATHS
# =============================================================================

PACKAGE_ROOT = Path(__file__).parent
PROJECT_ROOT = PACKAGE_ROOT.parent.parent
# 数据与模板目录：优先使用包内目录（已随 wheel 打包，pip 正式安装后依然可用）；
# 兼容回退到项目根目录（旧目录结构或数据未打包的场景）
DATA_DIR = PACKAGE_ROOT / "data"
if not DATA_DIR.exists():
    DATA_DIR = PROJECT_ROOT / "data"
TEMPLATES_DIR = PACKAGE_ROOT / "templates"
if not TEMPLATES_DIR.exists():
    TEMPLATES_DIR = PROJECT_ROOT / "templates"

# =============================================================================
# DEFAULT EXPLOIT PATTERNS
# =============================================================================

DEFAULT_EXPLOIT_PATTERNS = {
    "patterns": {
        "CVE-2024-4577": {
            "name": "PHP CGI Argument Injection",
            "severity": "critical",
            "patterns": [
                "%AD.*allow_url_include",
                "%AD.*auto_prepend_file",
                "php://input"
            ],
            "mitre_techniques": ["T1190"]
        },
        "CVE-2021-44228": {
            "name": "Log4Shell",
            "severity": "critical",
            "patterns": [
                "\\$\\{jndi:",
                "\\$\\{.*\\$\\{",
                "\\$\\{lower:",
                "\\$\\{upper:"
            ],
            "mitre_techniques": ["T1190", "T1059"]
        },
        "sql_injection": {
            "name": "SQL Injection",
            "severity": "high",
            "patterns": [
                "'\\s*(OR|AND)\\s*'.*'\\s*=\\s*'",
                "UNION\\s+(ALL\\s+)?SELECT",
                "SLEEP\\s*\\("
            ],
            "mitre_techniques": ["T1190"]
        },
        "path_traversal": {
            "name": "Path Traversal",
            "severity": "high",
            "patterns": [
                "\\.\\./",
                "%2e%2e/",
                "/etc/passwd",
                "C:\\\\Windows"
            ],
            "mitre_techniques": ["T1083"]
        },
        "command_injection": {
            "name": "Command Injection",
            "severity": "critical",
            "patterns": [
                ";\\s*(ls|cat|whoami|id)",
                "\\|\\s*(ls|cat|whoami)",
                "`.*`"
            ],
            "mitre_techniques": ["T1059"]
        },
        "webshell": {
            "name": "Webshell Indicators",
            "severity": "critical",
            "patterns": [
                "c99\\.php",
                "r57\\.php",
                "cmd\\.php\\?cmd=",
                "eval\\s*\\(\\s*\\$_(GET|POST)"
            ],
            "mitre_techniques": ["T1505.003"]
        }
    }
}

# =============================================================================
# DEFAULT C2 INDICATORS
# =============================================================================

DEFAULT_C2_INDICATORS = {
    "reverse_shell_patterns": {
        "bash_reverse": {
            "name": "Bash Reverse Shell",
            "patterns": [
                "/bin/bash\\s+-i",
                "bash\\s+-c.*>&.*0>&1",
                "/dev/tcp/"
            ],
            "mitre_techniques": ["T1059.004"]
        },
        "netcat_reverse": {
            "name": "Netcat Reverse Shell",
            "patterns": [
                "nc\\s+-e\\s+/bin/(ba)?sh",
                "nc\\s+-c\\s+/bin/(ba)?sh"
            ],
            "mitre_techniques": ["T1059.004"]
        },
        "python_reverse": {
            "name": "Python Reverse Shell",
            "patterns": [
                "python.*socket.*connect",
                "import\\s+socket.*subprocess"
            ],
            "mitre_techniques": ["T1059.006"]
        },
        "powershell_reverse": {
            "name": "PowerShell Reverse Shell",
            "patterns": [
                "powershell.*-e\\s+[A-Za-z0-9+/=]+",
                "IEX\\s*\\(",
                "Net\\.Sockets\\.TCPClient"
            ],
            "mitre_techniques": ["T1059.001"]
        }
    },
    "shell_command_patterns": {
        "reconnaissance": {
            "patterns": ["whoami", "id", "uname\\s+-a", "ifconfig", "ipconfig", "netstat"]
        },
        "persistence": {
            "patterns": ["crontab", "schtasks", "reg\\s+add"]
        },
        "lateral_movement": {
            "patterns": ["psexec", "wmic\\s+/node", "ssh\\s+", "net\\s+use"]
        }
    }
}

# =============================================================================
# DEFAULT MITRE MAPPING
# =============================================================================

DEFAULT_MITRE_MAPPING = {
    "techniques": {
        "T1190": {"name": "Exploit Public-Facing Application", "tactic": "initial_access"},
        "T1059": {"name": "Command and Scripting Interpreter", "tactic": "execution"},
        "T1059.001": {"name": "PowerShell", "tactic": "execution"},
        "T1059.004": {"name": "Unix Shell", "tactic": "execution"},
        "T1059.006": {"name": "Python", "tactic": "execution"},
        "T1071": {"name": "Application Layer Protocol", "tactic": "command_and_control"},
        "T1083": {"name": "File and Directory Discovery", "tactic": "discovery"},
        "T1505.003": {"name": "Web Shell", "tactic": "persistence"},
        "T1595.001": {"name": "Scanning IP Blocks", "tactic": "reconnaissance"}
    }
}

# =============================================================================
# PROTOCOL CONSTANTS
# =============================================================================

MCP_PROTOCOL_VERSION = "2024-11-05"
# 服务端可接受的 MCP 协议版本（initialize 时与客户端协商，无法匹配时回退 MCP_PROTOCOL_VERSION）
SUPPORTED_PROTOCOL_VERSIONS = ["2025-06-18", "2025-03-26", "2024-11-05"]
# initialize 应答中的 instructions 字段：向客户端（LLM）说明本服务的推荐用法
SERVER_INSTRUCTIONS = (
    "PCAP network forensics server. Typical workflow: call load_pcap with a pcap file "
    "path first, then run get_summary / detect_web_exploits / detect_port_scan / "
    "build_attack_timeline, and finally generate_html_report to export results."
)
MCP_SERVER_NAME = "pcap-analysis-mcp"
MCP_SERVER_VERSION = "1.0.3"

# =============================================================================
# ANALYSIS DEFAULTS
# =============================================================================

DEFAULT_PORT_SCAN_THRESHOLD = 15
# WebShell 疑似端点的最低 POST 次数（哥斯拉/冰蝎等加密 WebShell 会持续 POST 同一 .php 端点）
DEFAULT_WEBSHELL_POST_THRESHOLD = 3
DEFAULT_BEACON_INTERVAL_THRESHOLD = 60.0
DEFAULT_EXFIL_BYTES_THRESHOLD = 1000000

# Common service ports
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    3389: "RDP",
    5985: "WinRM",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt"
}

# Private IP ranges
PRIVATE_IP_PREFIXES = ['10.', '192.168.', '172.16.', '127.']


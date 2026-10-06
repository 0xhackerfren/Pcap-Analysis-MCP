# -*- coding: utf-8 -*-
"""
MCP Protocol Handler

Implements the Model Context Protocol (MCP) for stdio transport.
"""

import sys
import json
import logging
from typing import Any, Dict, Optional

logger = logging.getLogger("pcap-analysis-mcp.protocol")


class MCPProtocol:
    """Simple MCP stdio protocol handler for JSON-RPC communication."""

    @staticmethod
    def configure_streams() -> None:
        """
        将标准输入/输出/错误流强制配置为 UTF-8。

        Windows 中文环境默认编码为 GBK，会导致：
        - 客户端发来的 UTF-8 JSON（如含中文路径）解码失败；
        - 服务端写出的内容出现编码异常。
        MCP stdio 传输要求使用 UTF-8，此处统一修正。
        """
        for stream in (sys.stdin, sys.stdout, sys.stderr):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace", newline="\n")
            except (AttributeError, ValueError, OSError):
                # 个别环境下流对象不支持 reconfigure（如被第三方包装），忽略即可
                pass

    @staticmethod
    def read_message() -> Optional[Any]:
        """
        从 stdin 读取一条 JSON-RPC 消息（按行分隔的 NDJSON 格式）。

        空行与无法解析的脏行会被记录并跳过，服务继续运行；
        仅在读到 EOF（客户端断开）时返回 None。

        Returns:
            解析后的 JSON dict 或批量消息 list；EOF 时返回 None。
        """
        while True:
            try:
                line = sys.stdin.readline()
            except (ValueError, OSError):
                return None  # 输入流已关闭，等同于 EOF
            if not line:
                return None
            line = line.strip()
            if not line:
                continue  # 跳过空行
            try:
                return json.loads(line)
            except json.JSONDecodeError as e:
                # 跳过脏数据而非退出，避免单行异常导致整个服务终止
                logger.error(f"Skipping malformed JSON line: {e}")

    @staticmethod
    def write_message(msg: Any) -> None:
        """
        将 JSON-RPC 消息写入 stdout（单行 JSON + 换行符）。

        Args:
            msg: 要序列化并写出的消息（dict 或批量消息 list）。
        """
        sys.stdout.write(json.dumps(msg) + "\n")
        sys.stdout.flush()

    @staticmethod
    def success_response(req_id: Any, result: Any) -> Dict:
        """
        Create a JSON-RPC success response.

        Args:
            req_id: Request ID to echo back.
            result: Result payload.

        Returns:
            JSON-RPC response dict.
        """
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": result
        }

    @staticmethod
    def error_response(req_id: Any, code: int, message: str, data: Any = None) -> Dict:
        """
        Create a JSON-RPC error response.

        Args:
            req_id: Request ID to echo back.
            code: Error code (negative for JSON-RPC errors).
            message: Human-readable error message.
            data: Optional additional error data.

        Returns:
            JSON-RPC error response dict.
        """
        error = {"code": code, "message": message}
        if data is not None:
            error["data"] = data
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": error
        }

    @staticmethod
    def notification(method: str, params: Dict = None) -> Dict:
        """
        Create a JSON-RPC notification (no id, no response expected).

        Args:
            method: Method name.
            params: Optional parameters.

        Returns:
            JSON-RPC notification dict.
        """
        msg = {"jsonrpc": "2.0", "method": method}
        if params:
            msg["params"] = params
        return msg

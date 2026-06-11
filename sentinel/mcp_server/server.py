"""SIFT Sentinel MCP Server.

Read-only forensic analysis tools over MCP.
No write tool. No shell tool. No delete tool.
"""

from __future__ import annotations

import hashlib
import json
import time
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

from ..models import Citation, ToolResult
from .guards import MAX_OUTPUT_BYTES, MAX_ROWS, bound_rows, check_output_size, validate_evidence_path

server = Server("sift-sentinel")
_session_hashes: dict[str, str] = {}
_case_id: str = ""


def configure_server(case_id: str, session_hashes: dict[str, str]) -> None:
    global _case_id, _session_hashes
    _case_id = case_id
    _session_hashes = session_hashes


def build_tool_result(tool_name: str, args: dict, source_artifact: str,
                      rows: list[dict], citations: list[Citation],
                      start_time_ns: int) -> ToolResult:
    elapsed_ms = int((time.time_ns() - start_time_ns) / 1_000_000)
    bounded, truncated = bound_rows(rows, MAX_ROWS)
    serialized = json.dumps(bounded, default=str).encode()
    check_output_size(serialized, MAX_OUTPUT_BYTES)
    output_hash = hashlib.sha256(serialized).hexdigest()
    return ToolResult(
        tool_name=tool_name, case_id=_case_id, args=args,
        source_artifact=source_artifact,
        artifact_hash_at_session_start=_session_hashes.get(source_artifact, "unknown"),
        rows=bounded, citations=citations, truncated=truncated,
        execution_time_ms=elapsed_ms, output_hash=output_hash,
    )


@server.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(name="verify_image_hash",
             description="Compute SHA-256 of a disk image and compare against the session manifest.",
             inputSchema={"type": "object", "properties": {"image_path": {"type": "string"}}, "required": ["image_path"]}),
        Tool(name="list_partitions",
             description="List partition table entries for a disk image.",
             inputSchema={"type": "object", "properties": {"image_path": {"type": "string"}}, "required": ["image_path"]}),
        Tool(name="get_mft_timeline",
             description="Extract MFT entries within a UTC time range.",
             inputSchema={"type": "object", "properties": {
                 "image_path": {"type": "string"}, "start_utc": {"type": "string"},
                 "end_utc": {"type": "string"}, "path_filter": {"type": "string"},
             }, "required": ["image_path", "start_utc", "end_utc"]}),
        Tool(name="query_registry",
             description="Read a registry key and its values from an offline hive.",
             inputSchema={"type": "object", "properties": {
                 "image_path": {"type": "string"}, "hive": {"type": "string"},
                 "key_path": {"type": "string"}, "recursive": {"type": "boolean", "default": False},
             }, "required": ["image_path", "hive", "key_path"]}),
        Tool(name="parse_evtx",
             description="Parse Windows Event Log entries.",
             inputSchema={"type": "object", "properties": {
                 "image_path": {"type": "string"}, "log_name": {"type": "string"},
                 "event_ids": {"type": "array", "items": {"type": "integer"}},
                 "start_utc": {"type": "string"}, "end_utc": {"type": "string"},
             }, "required": ["image_path", "log_name"]}),
        Tool(name="parse_prefetch",
             description="Parse Windows Prefetch files.",
             inputSchema={"type": "object", "properties": {"image_path": {"type": "string"}}, "required": ["image_path"]}),
        Tool(name="parse_amcache",
             description="Parse AmCache hive for application execution history.",
             inputSchema={"type": "object", "properties": {"image_path": {"type": "string"}}, "required": ["image_path"]}),
        Tool(name="parse_shimcache",
             description="Parse ShimCache for evidence of program execution.",
             inputSchema={"type": "object", "properties": {"image_path": {"type": "string"}}, "required": ["image_path"]}),
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    if "image_path" in arguments:
        validate_evidence_path(arguments["image_path"])
    # TODO: Phase 2 -- wire up actual tool implementations
    return [TextContent(type="text", text=json.dumps({"error": f"Tool '{name}' not yet implemented"}))]


async def run_server() -> None:
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())

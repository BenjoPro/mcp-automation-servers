import asyncio
import logging
import os
import sys
from typing import Any

import mcp.server.stdio
from mcp.server import Server
from mcp.server.models import InitializationOptions
from mcp import types

from .tools import (
    google_dorking,
    shodan_tool,
    censys_tool,
    zoomeye_tool,
    fofa_tool,
    nmap_tool,
    modbus_tool,
    metasploit_tool,
    builtwith_tool,
    exploitdb_tool,
    cloudenum_tool,
)
from .utils.logger import setup_logger

logger = setup_logger(__name__)

TOOLS: list[types.Tool] = [
    types.Tool(
        name="google_dork_scada",
        description="Build and execute Google dork queries targeting SCADA/ICS/OT systems.",
        inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "dork_type": {"type": "string", "enum": ["hmi","plc","scada","modbus","dnp3","bacnet","custom"], "default": "scada"},
                "custom_dork": {"type": "string"},
                "num_results": {"type": "integer", "default": 10},
            },
            "required": ["target"],
        },
    ),
    types.Tool(
        name="shodan_scada_search",
        description="Search Shodan for exposed SCADA/ICS/OT devices.",
        inputSchema={
            "type": "object",
            "properties": {
                "query": {"type": "string"},
                "ip": {"type": "string"},
                "search_type": {"type": "string", "enum": ["search","host","ics_preset"], "default": "search"},
                "ics_preset": {"type": "string", "enum": ["modbus","dnp3","bacnet","ethernet_ip","s7","iec104","codesys","all"]},
                "max_results": {"type": "integer", "default": 20},
            },
        },
    ),
    types.Tool(
        name="censys_scada_search",
        description="Search Censys for SCADA/ICS/OT assets.",
        inputSchema={
            "type": "object",
            "properties": {
                "query": {"type": "string"},
                "ip": {"type": "string"},
                "search_type": {"type": "string", "enum": ["hosts","certs","host_view"], "default": "hosts"},
                "ics_preset": {"type": "string", "enum": ["modbus","dnp3","bacnet","s7","iec104","all"]},
                "max_results": {"type": "integer", "default": 20},
            },
        },
    ),
    types.Tool(
        name="zoomeye_scada_search",
        description="Search ZoomEye for SCADA/ICS/OT devices.",
        inputSchema={
            "type": "object",
            "properties": {
                "query": {"type": "string"},
                "search_type": {"type": "string", "enum": ["host","web"], "default": "host"},
                "ics_preset": {"type": "string", "enum": ["modbus","bacnet","dnp3","s7","all"]},
                "page": {"type": "integer", "default": 1},
                "max_results": {"type": "integer", "default": 20},
            },
        },
    ),
    types.Tool(
        name="fofa_scada_search",
        description="Search FOFA for SCADA/ICS/OT assets.",
        inputSchema={
            "type": "object",
            "properties": {
                "query": {"type": "string"},
                "ics_preset": {"type": "string", "enum": ["modbus","bacnet","dnp3","s7","iec104","all"]},
                "max_results": {"type": "integer", "default": 20},
                "fields": {"type": "string", "default": "ip,port,protocol,title,city,country"},
            },
        },
    ),
    types.Tool(
        name="nmap_ics_scan",
        description="Run Nmap with ICS/SCADA-specific NSE scripts against a target.",
        inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "scan_type": {"type": "string", "enum": ["ics_discovery","modbus","s7","bacnet","dnp3","full_ics","vuln","custom"], "default": "ics_discovery"},
                "ports": {"type": "string"},
                "timing": {"type": "string", "enum": ["T1","T2","T3","T4"], "default": "T3"},
                "extra_args": {"type": "string"},
            },
            "required": ["target"],
        },
    ),
    types.Tool(
        name="modbus_probe",
        description="Interact with Modbus TCP endpoints — read registers, coils, device info.",
        inputSchema={
            "type": "object",
            "properties": {
                "host": {"type": "string"},
                "port": {"type": "integer", "default": 502},
                "action": {"type": "string", "enum": ["device_info","read_coils","read_registers","read_inputs","scan_unit_ids"], "default": "device_info"},
                "unit_id": {"type": "integer", "default": 1},
                "start_address": {"type": "integer", "default": 0},
                "count": {"type": "integer", "default": 10},
                "timeout": {"type": "integer", "default": 5},
            },
            "required": ["host"],
        },
    ),
    types.Tool(
        name="metasploit_ics_scan",
        description="Run Metasploit auxiliary scanner modules for ICS/SCADA protocols.",
        inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "module": {"type": "string", "enum": ["modbus_findunitid","modbus_client","bacnet_device_info","profinet_dcp_discover","siemens_s7_info","dnp3_serial_info","ethernet_ip_list_identity","ics_preset_all"], "default": "ics_preset_all"},
                "port": {"type": "integer"},
                "timeout": {"type": "integer", "default": 30},
            },
            "required": ["target"],
        },
    ),
    types.Tool(
        name="builtwith_ics_lookup",
        description="Identify technology stacks on SCADA/HMI web interfaces using BuiltWith.",
        inputSchema={
            "type": "object",
            "properties": {
                "domain": {"type": "string"},
                "lookup_type": {"type": "string", "enum": ["technologies","detailed","relationships"], "default": "technologies"},
            },
            "required": ["domain"],
        },
    ),
    types.Tool(
        name="exploitdb_ics_search",
        description="Search Exploit-DB for known ICS/SCADA/OT vulnerabilities and exploits.",
        inputSchema={
            "type": "object",
            "properties": {
                "query": {"type": "string"},
                "search_type": {"type": "string", "enum": ["searchsploit","edb_api","cve"], "default": "searchsploit"},
                "cve": {"type": "string"},
                "exploit_type": {"type": "string", "enum": ["all","remote","local","dos","webapps"], "default": "all"},
                "include_poc": {"type": "boolean", "default": False},
            },
            "required": ["query"],
        },
    ),
    types.Tool(
        name="cloudenum_ics_scan",
        description="Discover cloud assets (S3, Azure Blob, GCP) belonging to ICS/OT vendors.",
        inputSchema={
            "type": "object",
            "properties": {
                "keyword": {"type": "string"},
                "extra_keywords": {"type": "array", "items": {"type": "string"}},
                "providers": {"type": "array", "items": {"type": "string", "enum": ["aws","azure","gcp"]}, "default": ["aws","azure","gcp"]},
                "timeout": {"type": "integer", "default": 120},
            },
            "required": ["keyword"],
        },
    ),
]

server = Server("scada-osint-mcp")

@server.list_tools()
async def list_tools() -> list[types.Tool]:
    return TOOLS

@server.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> list[types.TextContent]:
    logger.info(f"Tool called: {name} | args: {arguments}")
    try:
        result = await _dispatch(name, arguments)
    except Exception as exc:
        logger.exception(f"Tool {name} failed")
        result = f"[ERROR] {type(exc).__name__}: {exc}"
    return [types.TextContent(type="text", text=result)]

async def _dispatch(name: str, args: dict[str, Any]) -> str:
    dispatch_map = {
        "google_dork_scada":     google_dorking.run,
        "shodan_scada_search":   shodan_tool.run,
        "censys_scada_search":   censys_tool.run,
        "zoomeye_scada_search":  zoomeye_tool.run,
        "fofa_scada_search":     fofa_tool.run,
        "nmap_ics_scan":         nmap_tool.run,
        "modbus_probe":          modbus_tool.run,
        "metasploit_ics_scan":   metasploit_tool.run,
        "builtwith_ics_lookup":  builtwith_tool.run,
        "exploitdb_ics_search":  exploitdb_tool.run,
        "cloudenum_ics_scan":    cloudenum_tool.run,
    }
    handler = dispatch_map.get(name)
    if not handler:
        return f"[ERROR] Unknown tool: {name}"
    return await handler(args)

async def main() -> None:
    logger.info("Starting SCADA OSINT MCP Server...")
    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="scada-osint-mcp",
                server_version="1.0.0",
                capabilities=server.get_capabilities(
                    notification_options=mcp.server.NotificationOptions(),
                    experimental_capabilities={},
                ),
            ),
        )

if __name__ == "__main__":
    asyncio.run(main())





#!/usr/bin/env python3
import asyncio, json, os, base64
import httpx
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent, CallToolResult

app = Server("osint-extensions")

FOFA_EMAIL      = os.getenv("FOFA_EMAIL", "")
FOFA_API_KEY    = os.getenv("FOFA_API_KEY", "")
ZOOMEYE_API_KEY = os.getenv("ZOOMEYE_API_KEY", "")

@app.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(name="gau", description="Fetch all known URLs for a domain (Wayback, CommonCrawl, OTX, URLScan)",
             inputSchema={"type":"object","properties":{"domain":{"type":"string"},"subs":{"type":"boolean"},"max_results":{"type":"integer"}},"required":["domain"]}),
        Tool(name="sherlock", description="Hunt username across 400+ social networks",
             inputSchema={"type":"object","properties":{"username":{"type":"string"},"timeout":{"type":"integer"}},"required":["username"]}),
        Tool(name="fofa", description="Search FOFA internet-asset search engine",
             inputSchema={"type":"object","properties":{"query":{"type":"string"},"fields":{"type":"array","items":{"type":"string"}},"size":{"type":"integer"},"full":{"type":"boolean"}},"required":["query"]}),
        Tool(name="zoomeye", description="Search ZoomEye cyberspace search engine",
             inputSchema={"type":"object","properties":{"query":{"type":"string"},"search_type":{"type":"string","enum":["host","web"]},"page":{"type":"integer"},"size":{"type":"integer"}},"required":["query"]}),
    ]

def _truncate(text, n=200):
    lines = text.strip().splitlines()
    if len(lines) > n:
        lines = lines[:n] + [f"... (truncated to {n} results)"]
    return "\n".join(lines)

async def run_gau(domain, subs, max_results):
    cmd = ["gau", domain]
    if subs: cmd.append("--subs")
    try:
        proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)
        out = stdout.decode(errors="replace")
        return _truncate(out, max_results) if out.strip() else f"No results.\nstderr: {stderr.decode()}"
    except asyncio.TimeoutError: return "GAU timed out."
    except FileNotFoundError: return "ERROR: gau not found."

async def run_sherlock(username, timeout):
    cmd = ["python3", "/opt/sherlock/sherlock/sherlock.py", username, "--timeout", str(timeout), "--print-found"]
    try:
        proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=300)
        lines = [l for l in stdout.decode(errors="replace").splitlines() if "[+]" in l]
        return "\n".join(lines) if lines else f"No results for '{username}'."
    except asyncio.TimeoutError: return "Sherlock timed out."
    except FileNotFoundError: return "ERROR: Sherlock not found."

async def run_fofa(query, fields, size, full):
    if not FOFA_EMAIL or not FOFA_API_KEY: return "ERROR: FOFA credentials not set."
    qb64 = base64.b64encode(query.encode()).decode()
    field_str = ",".join(fields) if fields else "ip,port,domain,title,country,os,server"
    async with httpx.AsyncClient(timeout=30) as client:
        try:
            r = await client.get("https://fofa.info/api/v1/search/all",
                params={"email":FOFA_EMAIL,"key":FOFA_API_KEY,"qbase64":qb64,"fields":field_str,"size":min(size,10000),"full":str(full).lower()})
            r.raise_for_status()
            data = r.json()
        except Exception as e: return f"FOFA error: {e}"
    if data.get("error"): return f"FOFA API error: {data.get('errmsg')}"
    results = data.get("results", [])
    if not results: return f"No results for '{query}'."
    lines = [f"FOFA: {query} ({data.get('size',len(results))} total)\n", "  ".join(field_str.split(",")), "-"*60]
    for row in results: lines.append("  ".join(str(v) for v in row))
    return "\n".join(lines)

async def run_zoomeye(query, search_type, page, size):
    if not ZOOMEYE_API_KEY: return "ERROR: ZOOMEYE_API_KEY not set."
    ep = {"host":"https://api.zoomeye.org/host/search","web":"https://api.zoomeye.org/web/search"}[search_type]
    async with httpx.AsyncClient(timeout=30) as client:
        try:
            r = await client.get(ep, headers={"API-KEY":ZOOMEYE_API_KEY}, params={"query":query,"page":page})
            r.raise_for_status()
            data = r.json()
        except Exception as e: return f"ZoomEye error: {e}"
    matches = data.get("matches", [])
    if not matches: return f"No results for '{query}'."
    lines = [f"ZoomEye [{search_type}]: {query} ({data.get('total',0)} total)\n"]
    for i, m in enumerate(matches[:size], 1):
        if search_type == "host":
            pi = m.get("portinfo", {})
            country = m.get("geoinfo", {}).get("country", {}).get("names", {}).get("en", "")
            lines.append(f"[{i}] {m.get('ip')}:{pi.get('port')}  app={pi.get('app')}  {country}")
            if pi.get("banner"): lines.append(f"     {pi['banner'][:120]}")
        else:
            lines.append(f"[{i}] {m.get('site')}  {m.get('title')}  {m.get('ip',[''])[0]}")
    return "\n".join(lines)

@app.call_tool()
async def call_tool(name, arguments):
    try:
        if name == "gau":
            result = await run_gau(arguments["domain"], arguments.get("subs",False), arguments.get("max_results",200))
        elif name == "sherlock":
            result = await run_sherlock(arguments["username"], arguments.get("timeout",10))
        elif name == "fofa":
            result = await run_fofa(arguments["query"], arguments.get("fields"), arguments.get("size",100), arguments.get("full",False))
        elif name == "zoomeye":
            result = await run_zoomeye(arguments["query"], arguments.get("search_type","host"), arguments.get("page",1), arguments.get("size",20))
        else:
            result = f"Unknown tool: {name}"
    except Exception as e:
        result = f"Error in {name}: {e}"
    return CallToolResult(content=[TextContent(type="text", text=result)])

async def main():
    async with stdio_server() as (r, w):
        await app.run(r, w, app.create_initialization_options())

if __name__ == "__main__":
    asyncio.run(main())

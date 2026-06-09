"""
AI-Embedded-Wazuh — MCP Server
Gives Claude full access to a local Wazuh instance via the MCP stdio protocol.
Runs inside Docker on the shared wazuh network.
"""

import asyncio, json, os, urllib.request, urllib.error, ssl, base64
from typing import Any
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp import types

WAZUH_HOST     = os.getenv("WAZUH_HOST",     "https://wazuh.manager:55000")
WAZUH_USER     = os.getenv("WAZUH_USER",     "wazuh")
WAZUH_PASSWORD = os.getenv("WAZUH_PASSWORD", "wazuh")
VERIFY_SSL     = os.getenv("VERIFY_SSL",     "false").lower() == "true"

def _ssl_ctx():
    ctx = ssl.create_default_context()
    if not VERIFY_SSL:
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
    return ctx

def _get_token():
    creds = base64.b64encode(f"{WAZUH_USER}:{WAZUH_PASSWORD}".encode()).decode()
    req   = urllib.request.Request(
        f"{WAZUH_HOST}/security/user/authenticate",
        method="GET", headers={"Authorization": f"Basic {creds}"})
    with urllib.request.urlopen(req, context=_ssl_ctx(), timeout=10) as r:
        return json.loads(r.read())["data"]["token"]

def _api(method, path, body=None):
    token   = _get_token()
    payload = json.dumps(body).encode() if body else None
    req     = urllib.request.Request(
        f"{WAZUH_HOST}{path}", data=payload, method=method,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, context=_ssl_ctx(), timeout=15) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        return {"error": e.code, "reason": e.reason, "body": e.read().decode()}

app = Server("AI-Embedded-Wazuh")


@app.list_tools()
async def list_tools():
    return [
        types.Tool(name="get_alerts", description="Fetch recent Wazuh alerts. Filter by level (1-15), agent_id, group.",
            inputSchema={"type":"object","properties":{
                "limit":    {"type":"integer","default":20},
                "level":    {"type":"integer"},
                "agent_id": {"type":"string"},
                "group":    {"type":"string"},
                "offset":   {"type":"integer","default":0}}}),
        types.Tool(name="get_alert_summary", description="Top-N alert aggregation by level/agent/rule/group.",
            inputSchema={"type":"object","properties":{
                "group_by":{"type":"string","enum":["level","agent","rule","group"],"default":"level"},
                "limit":   {"type":"integer","default":10}}}),
        types.Tool(name="list_agents", description="List all agents with status, OS, IP, version.",
            inputSchema={"type":"object","properties":{
                "status":{"type":"string","enum":["active","disconnected","never_connected","pending","all"],"default":"all"},
                "limit": {"type":"integer","default":50},
                "search":{"type":"string"}}}),
        types.Tool(name="get_agent_info", description="Full details for one agent.",
            inputSchema={"type":"object","required":["agent_id"],"properties":{"agent_id":{"type":"string"}}}),
        types.Tool(name="restart_agent", description="Restart one or more agents remotely.",
            inputSchema={"type":"object","required":["agent_ids"],"properties":{"agent_ids":{"type":"array","items":{"type":"string"}}}}),
        types.Tool(name="delete_agent", description="Remove an agent from the manager.",
            inputSchema={"type":"object","required":["agent_id"],"properties":{
                "agent_id":{"type":"string"},"purge":{"type":"boolean","default":False}}}),
        types.Tool(name="search_logs", description="Keyword search in an agent syslog.",
            inputSchema={"type":"object","required":["agent_id","query"],"properties":{
                "agent_id":{"type":"string"},"query":{"type":"string"},
                "limit":{"type":"integer","default":50},"offset":{"type":"integer","default":0}}}),
        types.Tool(name="get_agent_processes", description="Running processes on an agent (syscollector).",
            inputSchema={"type":"object","required":["agent_id"],"properties":{
                "agent_id":{"type":"string"},"search":{"type":"string"},"limit":{"type":"integer","default":50}}}),
        types.Tool(name="get_agent_packages", description="Installed packages on an agent (syscollector).",
            inputSchema={"type":"object","required":["agent_id"],"properties":{
                "agent_id":{"type":"string"},"search":{"type":"string"},"limit":{"type":"integer","default":100}}}),
        types.Tool(name="run_active_response",
            description="Run an Active Response command on agents. Commands: firewall-drop, disable-account, restart-wazuh.",
            inputSchema={"type":"object","required":["agent_ids","command"],"properties":{
                "agent_ids":{"type":"array","items":{"type":"string"}},
                "command":  {"type":"string"},
                "arguments":{"type":"array","items":{"type":"string"}},
                "alert":    {"type":"object"}}}),
        types.Tool(name="get_manager_info",   description="Manager version and compile info.",
            inputSchema={"type":"object","properties":{}}),
        types.Tool(name="get_cluster_status", description="Cluster health and node list.",
            inputSchema={"type":"object","properties":{}}),
    ]


@app.call_tool()
async def call_tool(name, arguments):
    def out(data):
        return [types.TextContent(type="text", text=json.dumps(data, indent=2, ensure_ascii=False))]

    if name == "get_alerts":
        p = f"?limit={arguments.get('limit',20)}&offset={arguments.get('offset',0)}&sort=-timestamp"
        if arguments.get("level"):    p += f"&level={arguments['level']}"
        if arguments.get("agent_id"): p += f"&agents_list={arguments['agent_id']}"
        if arguments.get("group"):    p += f"&groups_list={arguments['group']}"
        return out(_api("GET", f"/alerts{p}"))

    if name == "get_alert_summary":
        g = arguments.get("group_by","level"); lim = arguments.get("limit",10)
        items = _api("GET","/alerts?limit=500&sort=-timestamp").get("data",{}).get("affected_items",[])
        counts = {}
        for a in items:
            if   g=="level":  key=f"Level {a.get('rule',{}).get('level','?')}"
            elif g=="agent":  key=a.get("agent",{}).get("name","unknown")
            elif g=="rule":   key=a.get("rule",{}).get("description","unknown")
            else:             grps=a.get("rule",{}).get("groups",["unknown"]); key=grps[0] if grps else "unknown"
            counts[key]=counts.get(key,0)+1
        return out({"group_by":g,"summary":dict(sorted(counts.items(),key=lambda x:x[1],reverse=True)[:lim])})

    if name == "list_agents":
        s=arguments.get("status","all"); p=f"?limit={arguments.get('limit',50)}&select=id,name,ip,status,os.name,version,lastKeepAlive"
        if s!="all":                p+=f"&status={s}"
        if arguments.get("search"): p+=f"&search={arguments['search']}"
        return out(_api("GET",f"/agents{p}"))

    if name == "get_agent_info":   return out(_api("GET",f"/agents?agents_list={arguments['agent_id']}"))
    if name == "restart_agent":    return out(_api("PUT",f"/agents/restart?agents_list={','.join(arguments['agent_ids'])}"))
    if name == "delete_agent":
        return out(_api("DELETE",f"/agents?agents_list={arguments['agent_id']}&purge={'true' if arguments.get('purge') else 'false'}&status=all"))

    if name == "search_logs":
        return out(_api("GET",f"/agents/{arguments['agent_id']}/logs?limit={arguments.get('limit',50)}&offset={arguments.get('offset',0)}&search={arguments['query']}"))

    if name == "get_agent_processes":
        p=f"?limit={arguments.get('limit',50)}"
        if arguments.get("search"): p+=f"&search={arguments['search']}"
        return out(_api("GET",f"/syscollector/{arguments['agent_id']}/processes{p}"))

    if name == "get_agent_packages":
        p=f"?limit={arguments.get('limit',100)}"
        if arguments.get("search"): p+=f"&search={arguments['search']}"
        return out(_api("GET",f"/syscollector/{arguments['agent_id']}/packages{p}"))

    if name == "run_active_response":
        body={"command":arguments["command"]}
        if arguments.get("arguments"): body["arguments"]=arguments["arguments"]
        if arguments.get("alert"):     body["alert"]=arguments["alert"]
        return out(_api("PUT",f"/active-response?agents_list={','.join(arguments['agent_ids'])}",body))

    if name == "get_manager_info":   return out(_api("GET","/manager/info"))
    if name == "get_cluster_status": return out({"status":_api("GET","/cluster/status"),"nodes":_api("GET","/cluster/nodes")})
    return out({"error":f"Unknown tool: {name}"})

async def main():
    async with stdio_server() as (r,w):
        await app.run(r, w, app.create_initialization_options())

if __name__ == "__main__":
    asyncio.run(main())

import os
from typing import Any
from ..utils.logger import setup_logger

logger = setup_logger(__name__)

ICS_PRESETS = {
    "modbus":  "services.port=502",
    "dnp3":    "services.port=20000",
    "bacnet":  "services.port=47808",
    "s7":      "services.port=102",
    "iec104":  "services.port=2404",
    "all":     "services.port=502 or services.port=20000 or services.port=47808 or services.port=102 or services.port=2404",
}

async def run(args: dict[str, Any]) -> str:
    api_token = os.getenv("CENSYS_API_TOKEN")
    if not api_token:
        return "[ERROR] CENSYS_API_TOKEN not set."

    try:
        from censys.search import CensysHosts
    except ImportError:
        return "[ERROR] censys package not installed."

    search_type = args.get("search_type", "hosts")
    max_results = min(args.get("max_results", 20), 100)

    try:
        if search_type == "host_view":
            ip = args.get("ip")
            if not ip:
                return "[ERROR] 'ip' is required for host_view."
            h = CensysHosts(api_id="", api_secret="", token=api_token)
            return _format_host(h.view(ip))

        preset = args.get("ics_preset")
        query = args.get("query") or (ICS_PRESETS.get(preset, "") if preset else "")
        if not query:
            return "[ERROR] Provide 'query' or 'ics_preset'."

        h = CensysHosts(token=api_token)
        results = list(h.search(query, per_page=min(max_results, 100)))
        return _format_search(results, query)

    except Exception as exc:
        return f"[ERROR] Censys: {exc}"

def _format_host(host):
    ip = host.get("ip", "?")
    lines = [
        "=" * 50,
        f"  CENSYS HOST: {ip}",
        "=" * 50,
        f"  AS  : {host.get('autonomous_system', {}).get('name', 'N/A')}",
        f"  Country: {host.get('location', {}).get('country', 'N/A')}",
    ]
    for svc in host.get("services", []):
        port = svc.get("port", "?")
        transport = svc.get("transport_protocol", "tcp")
        name = svc.get("service_name", "")
        banner = svc.get("banner", "")[:100]
        lines.append(f"\n  -- {port}/{transport} {name} --")
        if banner:
            lines.append(f"  {banner}")
    return "\n".join(lines)

def _format_search(results, query):
    lines = [
        "=" * 50,
        f"  CENSYS SEARCH - ICS/SCADA",
        f"  Query: {query}",
        f"  Results: {len(results)}",
        "=" * 50,
    ]
    for r in results:
        ip = r.get("ip", "?")
        services = r.get("services", [])
        ports = [f"{s.get('port')}/{s.get('transport_protocol','tcp')}" for s in services]
        lines.append(f"\n  {ip}  Ports: {', '.join(ports[:8])}")
        for s in services[:3]:
            lines.append(f"     {s.get('port')}: {s.get('service_name','?')}")
    return "\n".join(lines)

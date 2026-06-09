import os
from typing import Any
import httpx
from ..utils.logger import setup_logger

logger = setup_logger(__name__)

ZOOMEYE_BASE = "https://api.zoomeye.org"

ICS_PRESETS = {
    "modbus":  "port:502",
    "bacnet":  "port:47808",
    "dnp3":    "port:20000",
    "s7":      "port:102",
    "all":     "port:502 port:47808 port:20000 port:102 port:2404",
}

async def run(args: dict[str, Any]) -> str:
    api_key = os.getenv("ZOOMEYE_API_KEY")
    if not api_key:
        return "[ERROR] ZOOMEYE_API_KEY not set."

    preset = args.get("ics_preset")
    query = args.get("query") or (ICS_PRESETS.get(preset, "") if preset else "")
    if not query:
        return "[ERROR] Provide 'query' or 'ics_preset'."

    search_type = args.get("search_type", "host")
    page = args.get("page", 1)

    endpoint = f"{ZOOMEYE_BASE}/{search_type}/search"
    headers = {"API-KEY": api_key}
    params = {"query": query, "page": page}

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(endpoint, headers=headers, params=params)
            resp.raise_for_status()
            data = resp.json()
        return _format_results(data, query, search_type)
    except Exception as exc:
        return f"[ERROR] ZoomEye: {exc}"

def _format_results(data, query, search_type):
    total = data.get("total", 0)
    matches = data.get("matches", [])
    lines = [
        "=" * 50,
        f"  ZOOMEYE SEARCH [{search_type.upper()}]",
        f"  Query: {query}",
        f"  Total: {total} | Page results: {len(matches)}",
        "=" * 50,
    ]
    for m in matches:
        ip = m.get("ip", "?")
        port_info = m.get("portinfo", {})
        port = port_info.get("port", "?")
        app = port_info.get("app", "N/A")
        banner = port_info.get("banner", "")[:80].replace("\n", " ")
        geo = m.get("geoinfo", {})
        country = geo.get("country", {}).get("names", {}).get("en", "N/A")
        org = geo.get("organization", "N/A")
        lines.append(f"\n  {ip}:{port}  [{country}]  {org}")
        lines.append(f"  App: {app}")
        if banner:
            lines.append(f"  Banner: {banner}")
    return "\n".join(lines)


import base64
import os
from typing import Any
import httpx
from ..utils.logger import setup_logger

logger = setup_logger(__name__)

FOFA_BASE = "https://fofa.info/api/v1/search/all"

ICS_PRESETS = {
    "modbus":  'protocol="modbus"',
    "bacnet":  'protocol="bacnet"',
    "dnp3":    'protocol="dnp3"',
    "s7":      'protocol="s7"',
    "iec104":  'protocol="iec-104"',
    "all":     'protocol="modbus" || protocol="bacnet" || protocol="dnp3" || protocol="s7" || protocol="iec-104"',
}

async def run(args: dict[str, Any]) -> str:
    email = os.getenv("FOFA_EMAIL")
    api_key = os.getenv("FOFA_API_KEY")
    if not email or not api_key:
        return "[ERROR] FOFA_EMAIL / FOFA_API_KEY not set."

    preset = args.get("ics_preset")
    query = args.get("query") or (ICS_PRESETS.get(preset, "") if preset else "")
    if not query:
        return "[ERROR] Provide 'query' or 'ics_preset'."

    fields = args.get("fields", "ip,port,protocol,title,city,country")
    max_results = min(args.get("max_results", 20), 100)
    query_b64 = base64.b64encode(query.encode()).decode()

    params = {
        "email": email,
        "key": api_key,
        "qbase64": query_b64,
        "fields": fields,
        "size": max_results,
        "full": "false",
    }

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(FOFA_BASE, params=params)
            resp.raise_for_status()
            data = resp.json()
        return _format_results(data, query, fields)
    except Exception as exc:
        return f"[ERROR] FOFA: {exc}"

def _format_results(data, query, fields):
    if data.get("error"):
        return f"[ERROR] FOFA API: {data.get('errmsg', 'Unknown error')}"

    total = data.get("size", 0)
    results = data.get("results", [])
    field_list = [f.strip() for f in fields.split(",")]

    lines = [
        "=" * 50,
        f"  FOFA SEARCH — ICS/SCADA",
        f"  Query: {query}",
        f"  Total: {total} | Showing: {len(results)}",
        "=" * 50,
    ]
    for row in results:
        record = dict(zip(field_list, row))
        ip = record.get("ip", "?")
        port = record.get("port", "?")
        proto = record.get("protocol", "N/A")
        country = record.get("country", "N/A")
        city = record.get("city", "N/A")
        title = record.get("title", "")
        lines.append(f"\n  {ip}:{port}  [{country}/{city}]  protocol={proto}")
        if title:
            lines.append(f"  Title: {title[:80]}")
    return "\n".join(lines)


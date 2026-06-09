import os
from typing import Any
import httpx
from ..utils.logger import setup_logger

logger = setup_logger(__name__)

BUILTWITH_BASE = "https://api.builtwith.com"

ICS_KEYWORDS = [
    "scada", "hmi", "plc", "historian", "wonderware", "ignition",
    "factorytalk", "ge digital", "siemens", "osisoft", "pi system",
    "kepware", "opc", "modbus", "bacnet", "industrial", "automation",
    "aveva", "honeywell", "schneider", "allen-bradley", "rockwell",
    "mitsubishi", "omron", "codesys",
]

async def run(args: dict[str, Any]) -> str:
    api_key = os.getenv("BUILTWITH_API_KEY")
    if not api_key:
        return "[ERROR] BUILTWITH_API_KEY not set."

    domain = args.get("domain")
    if not domain:
        return "[ERROR] 'domain' is required."

    lookup_type = args.get("lookup_type", "technologies")
    url = f"{BUILTWITH_BASE}/v21/api.json"
    params = {"KEY": api_key, "LOOKUP": domain}

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(url, params=params)
            resp.raise_for_status()
            data = resp.json()
        return _format_results(data, domain)
    except Exception as exc:
        return f"[ERROR] BuiltWith: {exc}"

def _format_results(data, domain):
    lines = [
        "=" * 50,
        f"  BUILTWITH — {domain.upper()}",
        "=" * 50,
    ]

    results = data.get("Results", [{}])
    if not results:
        lines.append("  No results found.")
        return "\n".join(lines)

    paths = results[0].get("Result", {}).get("Paths", [])
    ics_related = []
    all_tech = {}

    for path in paths:
        for tech in path.get("Technologies", []):
            name = tech.get("Name", "")
            cat = tech.get("Categories", ["Other"])[0] if tech.get("Categories") else "Other"
            all_tech.setdefault(cat, []).append(name)
            if any(kw in name.lower() for kw in ICS_KEYWORDS):
                ics_related.append(f"{name} [{cat}]")

    if ics_related:
        lines += ["", "  ICS/OT Relevant Technologies:"]
        for t in ics_related:
            lines.append(f"    *** {t}")

    lines += ["", "  All Technologies by Category:"]
    for cat, techs in sorted(all_tech.items()):
        lines.append(f"\n  [{cat}]")
        for t in techs[:10]:
            lines.append(f"    - {t}")

    lines.append("\n" + "=" * 50)
    return "\n".join(lines)


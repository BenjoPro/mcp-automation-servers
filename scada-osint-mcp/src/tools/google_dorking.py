import json
import os
from typing import Any
import httpx
from ..utils.logger import setup_logger

logger = setup_logger(__name__)

DORK_TEMPLATES = {
    "hmi": [
        'intitle:"SCADA" inurl:"/main.htm"',
        'intitle:"HMI" inurl:"login" filetype:html',
        'intitle:"Wonderware" inurl:"default.htm"',
        'intitle:"iFIX" inurl:"login.aspx"',
        'intitle:"Ignition" inurl:":8088"',
    ],
    "plc": [
        'intitle:"Siemens" inurl:"/Portal/portal"',
        'intitle:"Allen-Bradley" inurl:"index.htm"',
        'intitle:"Modicon" inurl:"index.htm"',
        'inurl:"/webvisu.htm" intitle:"WebVisu"',
        'intitle:"CODESYS" inurl:"WebVisu"',
    ],
    "scada": [
        'intitle:"SCADA Login"',
        'inurl:"scada" inurl:"login" -demo -test',
        'intitle:"OSIsoft PI" inurl:"PIWebAPI"',
        'intitle:"ClearSCADA" inurl:"ClearSCADA"',
        'intitle:"Inductive Automation" inurl:"8088"',
        '"Powered by Ignition" inurl:":8088"',
        'intitle:"FactoryTalk" inurl:"login"',
    ],
    "modbus": [
        'inurl:":502" intitle:"Modbus"',
        '"Modbus TCP" inurl:"config"',
        'filetype:cfg "ModbusSettings"',
    ],
    "dnp3": [
        '"DNP3" inurl:"config" filetype:xml',
        '"DNP3 outstation" intitle:"configuration"',
        'filetype:ini "dnp3" "master address"',
    ],
    "bacnet": [
        'intitle:"BACnet" inurl:"bbmd"',
        '"BACnet/IP" inurl:"config"',
        'intitle:"Building Automation" inurl:"bacnet"',
    ],
}

async def run(args: dict[str, Any]) -> str:
    target = args.get("target", "")
    dork_type = args.get("dork_type", "scada")
    custom_dork = args.get("custom_dork", "")
    num_results = min(args.get("num_results", 10), 100)

    api_key = os.getenv("GOOGLE_API_KEY")
    cse_id = os.getenv("GOOGLE_CSE_ID")

    if dork_type == "custom":
        dorks = [custom_dork] if custom_dork else []
    else:
        base = DORK_TEMPLATES.get(dork_type, DORK_TEMPLATES["scada"])
        dorks = [f'{d} "{target}"' if target else d for d in base]

    if not dorks:
        return "[ERROR] No dorks generated."

    if not api_key or not cse_id:
        return _format_dry_run(dorks, target, dork_type)

    results_output = []
    async with httpx.AsyncClient(timeout=30) as client:
        for dork in dorks[:5]:
            params = {"key": api_key, "cx": cse_id, "q": dork, "num": min(num_results, 10)}
            try:
                resp = await client.get("https://www.googleapis.com/customsearch/v1", params=params)
                resp.raise_for_status()
                data = resp.json()
                items = data.get("items", [])
                results_output.append({
                    "dork": dork,
                    "total_results": data.get("searchInformation", {}).get("totalResults", "0"),
                    "results": [{"title": i.get("title"), "url": i.get("link"), "snippet": i.get("snippet")} for i in items],
                })
            except Exception as exc:
                results_output.append({"dork": dork, "error": str(exc)})

    return _format_results(results_output, target, dork_type)

def _format_dry_run(dorks, target, dork_type):
    lines = [
        "=" * 50,
        f"  GOOGLE DORK GENERATOR [{dork_type.upper()}]",
        f"  Target: {target or '(none)'}",
        "=" * 50,
        "",
        "API keys not set — returning dork queries for manual use.",
        "",
        "Generated Dorks:",
    ]
    for i, d in enumerate(dorks, 1):
        lines.append(f"  [{i}] {d}")
    return "\n".join(lines)

def _format_results(results, target, dork_type):
    lines = [
        "=" * 50,
        f"  GOOGLE DORK RESULTS [{dork_type.upper()}]",
        f"  Target: {target}",
        "=" * 50,
    ]
    for entry in results:
        lines.append(f"\nDork: {entry['dork']}")
        if "error" in entry:
            lines.append(f"  Error: {entry['error']}")
        else:
            lines.append(f"  Total: {entry.get('total_results', '?')}")
            for r in entry.get("results", []):
                lines.append(f"\n  {r['title']}")
                lines.append(f"  URL: {r['url']}")
                lines.append(f"  {r.get('snippet','')[:120]}")
    return "\n".join(lines)


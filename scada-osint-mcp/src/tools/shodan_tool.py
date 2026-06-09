import os
from typing import Any
from ..utils.logger import setup_logger

logger = setup_logger(__name__)

ICS_PRESETS = {
    "modbus":      'port:502 "Modbus"',
    "dnp3":        'port:20000 "DNP"',
    "bacnet":      'port:47808 "BACnet"',
    "ethernet_ip": 'port:44818 "EtherNet/IP"',
    "s7":          'port:102 "Siemens S7"',
    "iec104":      'port:2404 "IEC 60870-5"',
    "codesys":     '"CODESYS" port:4840',
    "all": 'port:502 OR port:20000 OR port:47808 OR port:44818 OR port:102 OR port:2404 OR port:4840',
}

async def run(args: dict[str, Any]) -> str:
    api_key = os.getenv("SHODAN_API_KEY")
    if not api_key:
        return "[ERROR] SHODAN_API_KEY not set."

    try:
        import shodan
    except ImportError:
        return "[ERROR] shodan package not installed."

    api = shodan.Shodan(api_key)
    search_type = args.get("search_type", "search")
    max_results = min(args.get("max_results", 20), 100)

    try:
        if search_type == "host":
            ip = args.get("ip")
            if not ip:
                return "[ERROR] 'ip' is required for host lookup."
            return _format_host(api.host(ip))

        preset = args.get("ics_preset")
        query = args.get("query") or (ICS_PRESETS.get(preset, "") if preset else "")
        if not query:
            return "[ERROR] Provide 'query' or 'ics_preset'."

        results = api.search(query, limit=max_results)
        return _format_search(results, query)

    except Exception as exc:
        return f"[ERROR] Shodan: {exc}"

def _format_host(host):
    lines = [
        "=" * 50,
        f"  SHODAN HOST: {host.get('ip_str', '?')}",
        "=" * 50,
        f"  Org     : {host.get('org', 'N/A')}",
        f"  Country : {host.get('country_name', 'N/A')}",
        f"  OS      : {host.get('os', 'N/A')}",
        f"  Ports   : {', '.join(str(p) for p in host.get('ports', []))}",
    ]
    vulns = host.get("vulns", {})
    if vulns:
        lines.append("\n  CVEs:")
        for cve, info in list(vulns.items())[:10]:
            lines.append(f"    [{info.get('cvss','?')}] {cve} — {info.get('summary','')[:80]}")
    for banner in host.get("data", []):
        port = banner.get("port", "?")
        transport = banner.get("transport", "tcp")
        product = banner.get("product", "")
        lines.append(f"\n  -- Port {port}/{transport} {product} --")
        lines.append(f"  {banner.get('data','')[:200].strip()}")
    return "\n".join(lines)

def _format_search(results, query):
    total = results.get("total", 0)
    matches = results.get("matches", [])
    lines = [
        "=" * 50,
        f"  SHODAN SEARCH — ICS/SCADA",
        f"  Query: {query}",
        f"  Total: {total} | Showing: {len(matches)}",
        "=" * 50,
    ]
    for m in matches:
        ip = m.get("ip_str", "?")
        port = m.get("port", "?")
        org = m.get("org", "N/A")
        country = m.get("location", {}).get("country_name", "N/A")
        product = m.get("product", "")
        banner = m.get("data", "")[:100].replace("\n", " ")
        vulns = list(m.get("vulns", {}).keys())
        lines.append(f"\n  {ip}:{port}  [{country}]  {org}")
        lines.append(f"  Product : {product or 'N/A'}")
        lines.append(f"  Banner  : {banner}")
        if vulns:
            lines.append(f"  CVEs    : {', '.join(vulns[:5])}")
    return "\n".join(lines)


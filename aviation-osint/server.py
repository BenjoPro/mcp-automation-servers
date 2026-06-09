"""
Aviation-OSINT MCP Server
Real-time air traffic analysis via adsb.lol API
"""

import asyncio
import math
import httpx
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp import types

BASE_URL = "https://api.adsb.lol/v2"
HEADERS  = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

app = Server("aviation-osint")


async def fetch(path: str) -> dict:
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.get(f"{BASE_URL}{path}", headers=HEADERS)
        r.raise_for_status()
        return r.json()


def haversine(lat1, lon1, lat2, lon2) -> float:
    R = 6371
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp = math.radians(lat2 - lat1)
    dl = math.radians(lon2 - lon1)
    a = math.sin(dp/2)**2 + math.cos(p1)*math.cos(p2)*math.sin(dl/2)**2
    return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))


def fmt(ac: dict) -> str:
    L = []
    L.append(f"✈  ICAO: {ac.get('hex','?').upper()}")
    if ac.get('flight'):               L.append(f"   Flight:    {ac['flight'].strip()}")
    if ac.get('r'):                    L.append(f"   Reg:       {ac['r']}")
    if ac.get('t'):                    L.append(f"   Type:      {ac['t']}")
    if ac.get('lat') is not None:      L.append(f"   Position:  {ac['lat']:.4f}, {ac['lon']:.4f}")
    if ac.get('alt_baro') is not None: L.append(f"   Altitude:  {ac['alt_baro']} ft")
    if ac.get('gs') is not None:       L.append(f"   Speed:     {ac['gs']} kt")
    if ac.get('track') is not None:    L.append(f"   Heading:   {ac['track']}°")
    if ac.get('squawk'):               L.append(f"   Squawk:    {ac['squawk']}")
    if ac.get('seen') is not None:     L.append(f"   Last seen: {ac['seen']}s ago")
    return "\n".join(L)


@app.list_tools()
async def list_tools() -> list[types.Tool]:
    return [
        types.Tool(name="get_aircraft_by_icao",
            description="Look up aircraft by ICAO hex address.",
            inputSchema={"type":"object","properties":{"icao":{"type":"string"}},"required":["icao"]}),
        types.Tool(name="get_aircraft_by_callsign",
            description="Find aircraft by callsign or flight number.",
            inputSchema={"type":"object","properties":{"callsign":{"type":"string"}},"required":["callsign"]}),
        types.Tool(name="get_aircraft_by_registration",
            description="Find aircraft by tail number or registration.",
            inputSchema={"type":"object","properties":{"registration":{"type":"string"}},"required":["registration"]}),
        types.Tool(name="get_aircraft_by_type",
            description="Find all tracked aircraft of a given ICAO type code (e.g. B738, A320, F16).",
            inputSchema={"type":"object","properties":{"type_code":{"type":"string"},"limit":{"type":"integer","default":20}},"required":["type_code"]}),
        types.Tool(name="get_aircraft_in_radius",
            description="Find all aircraft within a radius in nautical miles around a lat/lon point.",
            inputSchema={"type":"object","properties":{"lat":{"type":"number"},"lon":{"type":"number"},"radius_nm":{"type":"number"},"limit":{"type":"integer","default":30}},"required":["lat","lon","radius_nm"]}),
        types.Tool(name="get_military_aircraft",
            description="Get all currently tracked military aircraft worldwide.",
            inputSchema={"type":"object","properties":{"limit":{"type":"integer","default":30}}}),
        types.Tool(name="get_ladd_aircraft",
            description="Get aircraft on the FAA LADD privacy list.",
            inputSchema={"type":"object","properties":{"limit":{"type":"integer","default":20}}}),
        types.Tool(name="get_aircraft_squawk",
            description="Find all aircraft transmitting a specific squawk code.",
            inputSchema={"type":"object","properties":{"squawk":{"type":"string"}},"required":["squawk"]}),
        types.Tool(name="analyze_area_traffic",
            description="Full traffic analysis for an area: counts, categories, altitudes, military.",
            inputSchema={"type":"object","properties":{"lat":{"type":"number"},"lon":{"type":"number"},"radius_nm":{"type":"number"},"area_name":{"type":"string"}},"required":["lat","lon","radius_nm"]}),
        types.Tool(name="get_closest_aircraft",
            description="Find the N closest aircraft to a given coordinate.",
            inputSchema={"type":"object","properties":{"lat":{"type":"number"},"lon":{"type":"number"},"count":{"type":"integer","default":5}},"required":["lat","lon"]}),
        types.Tool(name="debug_ip",
            description="Check what outbound IP the server uses and test API connectivity.",
            inputSchema={"type":"object","properties":{}}),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[types.TextContent]:

    def r(text): return [types.TextContent(type="text", text=text)]

    if name == "get_aircraft_by_icao":
        icao = arguments["icao"].lower().strip()
        data = await fetch(f"/icao/{icao}")
        ac = data.get("ac", [])
        return r(f"No aircraft found with ICAO {icao.upper()}.") if not ac else r(f"ICAO {icao.upper()}:\n\n{fmt(ac[0])}")

    elif name == "get_aircraft_by_callsign":
        cs = arguments["callsign"].strip().upper().replace(" ","")
        data = await fetch(f"/callsign/{cs}")
        ac = data.get("ac", [])
        return r(f"No aircraft found with callsign {cs}.") if not ac else r(f"Callsign {cs}:\n\n{fmt(ac[0])}")

    elif name == "get_aircraft_by_registration":
        reg = arguments["registration"].strip().upper().replace("-","")
        data = await fetch(f"/reg/{reg}")
        ac = data.get("ac", [])
        return r(f"No aircraft found with registration {reg}.") if not ac else r(f"Registration {reg}:\n\n{fmt(ac[0])}")

    elif name == "get_aircraft_by_type":
        tc    = arguments["type_code"].strip().upper()
        limit = min(int(arguments.get("limit", 20)), 100)
        data  = await fetch(f"/type/{tc}")
        acs   = data.get("ac", [])[:limit]
        if not acs: return r(f"No aircraft of type {tc} currently tracked.")
        parts = [f"Type {tc} — {len(acs)} aircraft:\n"]
        for ac in acs: parts += [fmt(ac), ""]
        return r("\n".join(parts))

    elif name == "get_aircraft_in_radius":
        lat  = float(arguments["lat"])
        lon  = float(arguments["lon"])
        dist = min(float(arguments["radius_nm"]), 250)
        lim  = min(int(arguments.get("limit", 30)), 200)
        data = await fetch(f"/lat/{lat}/lon/{lon}/dist/{dist}")
        acs  = data.get("ac", [])[:lim]
        tot  = data.get("total", len(acs))
        if not acs: return r(f"No aircraft within {dist} nm of ({lat}, {lon}).")
        parts = [f"{tot} aircraft within {dist} nm — showing {len(acs)}:\n"]
        for ac in acs: parts += [fmt(ac), ""]
        return r("\n".join(parts))

    elif name == "get_military_aircraft":
        lim  = min(int(arguments.get("limit", 30)), 200)
        data = await fetch("/mil")
        acs  = data.get("ac", [])[:lim]
        tot  = data.get("total", len(acs))
        if not acs: return r("No military aircraft currently tracked.")
        parts = [f"Military aircraft: {tot} total — showing {len(acs)}:\n"]
        for ac in acs: parts += [fmt(ac), ""]
        return r("\n".join(parts))

    elif name == "get_ladd_aircraft":
        lim  = min(int(arguments.get("limit", 20)), 100)
        data = await fetch("/ladd")
        acs  = data.get("ac", [])[:lim]
        tot  = data.get("total", len(acs))
        if not acs: return r("No LADD aircraft currently tracked.")
        parts = [f"LADD aircraft: {tot} total — showing {len(acs)}:\n"]
        for ac in acs: parts += [fmt(ac), ""]
        return r("\n".join(parts))

    elif name == "get_aircraft_squawk":
        sq   = arguments["squawk"].strip()
        data = await fetch(f"/squawk/{sq}")
        acs  = data.get("ac", [])
        if not acs: return r(f"No aircraft squawking {sq}.")
        parts = [f"Squawk {sq} — {len(acs)} aircraft:\n"]
        for ac in acs: parts += [fmt(ac), ""]
        return r("\n".join(parts))

    elif name == "analyze_area_traffic":
        lat   = float(arguments["lat"])
        lon   = float(arguments["lon"])
        dist  = float(arguments["radius_nm"])
        label = arguments.get("area_name", f"({lat:.3f}, {lon:.3f})")
        data  = await fetch(f"/lat/{lat}/lon/{lon}/dist/{dist}")
        acs   = data.get("ac", [])
        total = len(acs)
        if total == 0: return r(f"No aircraft in {label} ({dist} nm radius).")
        cats = {}
        for ac in acs:
            c = ac.get("category","Unknown"); cats[c] = cats.get(c,0)+1
        ground = sum(1 for a in acs if a.get("alt_baro")=="ground" or (a.get("gs",999)<30))
        low    = sum(1 for a in acs if isinstance(a.get("alt_baro"),(int,float)) and a["alt_baro"]<5000)
        mid    = sum(1 for a in acs if isinstance(a.get("alt_baro"),(int,float)) and 5000<=a["alt_baro"]<25000)
        high   = sum(1 for a in acs if isinstance(a.get("alt_baro"),(int,float)) and a["alt_baro"]>=25000)
        mil    = [a for a in acs if a.get("military")]
        ops = {}
        for a in acs:
            cs = (a.get("flight") or "").strip()
            if cs:
                pfx = "".join(c for c in cs if c.isalpha())[:3]
                if pfx: ops[pfx] = ops.get(pfx,0)+1
        top = sorted(ops.items(), key=lambda x:-x[1])[:5]
        lines = [
            f"📡 AVIATION ANALYSIS — {label}",
            f"   Radius: {dist} nm  |  Aircraft: {total}", "",
            "── Altitude ──────────────────────────────",
            f"   Ground        : {ground}",
            f"   < 5,000 ft    : {low}",
            f"   5k–25k ft     : {mid}",
            f"   > 25,000 ft   : {high}", "",
            "── Categories ────────────────────────────",
        ] + [f"   {k:20s}: {v}" for k,v in sorted(cats.items(),key=lambda x:-x[1])] + [
            "", "── Top Operators ─────────────────────────",
        ] + ([f"   {o:20s}: {c}" for o,c in top] if top else ["   (no callsigns)"]) + [
            "", f"── Military: {len(mil)} ───────────────────────────",
        ] + [f"   {a.get('hex','?').upper()} {(a.get('flight') or '').strip()} {a.get('t','')}" for a in mil]
        return r("\n".join(lines))

    elif name == "get_closest_aircraft":
        lat   = float(arguments["lat"])
        lon   = float(arguments["lon"])
        count = min(int(arguments.get("count", 5)), 50)
        data  = await fetch(f"/lat/{lat}/lon/{lon}/dist/100")
        acs   = data.get("ac", [])
        if len(acs) < count:
            data = await fetch(f"/lat/{lat}/lon/{lon}/dist/250")
            acs  = data.get("ac", [])
        with_pos = [a for a in acs if a.get("lat") is not None and a.get("lon") is not None]
        with_pos.sort(key=lambda a: haversine(lat, lon, a["lat"], a["lon"]))
        closest = with_pos[:count]
        if not closest: return r(f"No aircraft with position near ({lat}, {lon}).")
        parts = [f"Closest {len(closest)} aircraft to ({lat:.4f}, {lon:.4f}):\n"]
        for a in closest:
            d = haversine(lat, lon, a["lat"], a["lon"])
            parts += [f"📍 {d:.1f} km  ({d/1.852:.1f} nm)", fmt(a), ""]
        return r("\n".join(parts))

    elif name == "debug_ip":
        async with httpx.AsyncClient(timeout=10) as client:
            ip   = (await client.get("https://api.ipify.org")).text
            code = (await client.get("https://api.adsb.lol/v2/mil")).status_code
            return r(f"Outbound IP: {ip}\n/v2/mil status: {code}")

    else:
        return r(f"Unknown tool: {name}")


async def main():
    async with stdio_server() as (read, write):
        await app.run(read, write, app.create_initialization_options())

if __name__ == "__main__":
    asyncio.run(main())


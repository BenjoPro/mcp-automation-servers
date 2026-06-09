import asyncio
import httpx
from bs4 import BeautifulSoup
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp import types

app = Server("darkweb-search")

TOR_PROXY = "socks5://127.0.0.1:9050"

ENGINES = {
    "torch": "http://torchdeedp3i2jigzjdmfpn5ttjhthh5wbmda2rr3jvqjg5p77c54dqd.onion/search?query={query}&action=search",
    "tor66": "http://tor66sewebgixwhcqfnp5inzp5x5uohhdy3kvvo3nf4wnaway5uye3qd.onion/search?q={query}",
    "deepsearch": "http://searchgf7gdtauh7bhnbyed4ivxqmuoat3nm6zfrg3ymkq6mtnpye3ad.onion/?q={query}",
    "haystak": "http://haystak5njsmn2hqkewecpaxetahtwhsbsa64jom2k22z5afxhnpxfid.onion/?q={query}",
    "hiddenwiki": "http://zqktlwiuavvvqqt4ybvgvi7tyo4hjl5xgfuvpdf6otjiycgwqbym2qad.onion/wiki/index.php/Main_Page",
}

async def tor_get(url: str, timeout: int = 30) -> str:
    transport = httpx.AsyncHTTPTransport(proxy=TOR_PROXY)
    async with httpx.AsyncClient(transport=transport, timeout=timeout, follow_redirects=True) as client:
        r = await client.get(url)
        r.raise_for_status()
        return r.text

def parse_results(html: str, engine: str) -> list[dict]:
    soup = BeautifulSoup(html, "lxml")
    results = []

    if engine == "torch":
        for item in soup.select(".result")[:10]:
            title_el = item.select_one("h4 a") or item.select_one("a")
            snippet_el = item.select_one("p")
            if title_el:
                results.append({
                    "title": title_el.get_text(strip=True),
                    "url": title_el.get("href", ""),
                    "snippet": snippet_el.get_text(strip=True) if snippet_el else "",
                })

    elif engine == "tor66":
        for item in soup.select(".result, article, .sr")[:10]:
            title_el = item.select_one("a")
            snippet_el = item.select_one("p, .snippet, span")
            if title_el:
                results.append({
                    "title": title_el.get_text(strip=True),
                    "url": title_el.get("href", ""),
                    "snippet": snippet_el.get_text(strip=True) if snippet_el else "",
                })

    elif engine in ("deepsearch", "haystak"):
        for item in soup.select("li, .result, .item")[:10]:
            title_el = item.select_one("a")
            snippet_el = item.select_one("p, span, div")
            if title_el:
                results.append({
                    "title": title_el.get_text(strip=True),
                    "url": title_el.get("href", ""),
                    "snippet": snippet_el.get_text(strip=True) if snippet_el else "",
                })

    elif engine == "hiddenwiki":
        for item in soup.select("table a, #mw-content-text a")[:20]:
            href = item.get("href", "")
            if href and not href.startswith("#"):
                results.append({
                    "title": item.get_text(strip=True),
                    "url": href if href.startswith("http") else "http://zqktlwiuavvvqqt4ybvgvi7tyo4hjl5xgfuvpdf6otjiycgwqbym2qad.onion" + href,
                    "snippet": "",
                })

    if not results:
        for a in soup.select("a[href*='.onion']")[:10]:
            results.append({
                "title": a.get_text(strip=True) or a.get("href", ""),
                "url": a.get("href", ""),
                "snippet": "",
            })

    return results


@app.list_tools()
async def list_tools() -> list[types.Tool]:
    return [
        types.Tool(
            name="darkweb_search",
            description="Search the dark web using Torch, Tor66, DeepSearch, Haystak, or The Hidden Wiki via Tor network.",
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Search query"
                    },
                    "engines": {
                        "type": "array",
                        "items": {"type": "string", "enum": ["torch", "tor66", "deepsearch", "haystak", "hiddenwiki"]},
                        "description": "Which engines to search. Defaults to all.",
                        "default": ["torch", "tor66", "deepsearch", "haystak", "hiddenwiki"]
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Request timeout in seconds (default: 30)",
                        "default": 30
                    }
                },
                "required": ["query"]
            }
        ),
        types.Tool(
            name="tor_status",
            description="Check if the Tor connection is working.",
            inputSchema={"type": "object", "properties": {}}
        ),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[types.TextContent]:

    if name == "tor_status":
        try:
            html = await tor_get("http://check.torproject.org", timeout=20)
            ok = "Congratulations" in html or "tor" in html.lower()
            return [types.TextContent(type="text", text=f"Tor is {'working' if ok else 'NOT working properly'}")]
        except Exception as e:
            return [types.TextContent(type="text", text=f"Tor connection failed: {e}")]

    if name == "darkweb_search":
        query = arguments["query"]
        engines = arguments.get("engines", list(ENGINES.keys()))
        timeout = arguments.get("timeout", 30)
        all_results = {}

        async def search_engine(engine_name: str):
            try:
                url = ENGINES[engine_name].format(query=httpx.URL(query))
                html = await tor_get(url, timeout=timeout)
                results = parse_results(html, engine_name)
                all_results[engine_name] = results
            except Exception as e:
                all_results[engine_name] = {"error": str(e)}

        await asyncio.gather(*[search_engine(e) for e in engines if e in ENGINES])

        output = [f"# Dark Web Search: '{query}'\n"]
        for engine, results in all_results.items():
            output.append(f"\n## {engine.upper()}")
            if isinstance(results, dict) and "error" in results:
                output.append(f"Error: {results['error']}")
            elif not results:
                output.append("No results found.")
            else:
                for i, r in enumerate(results, 1):
                    output.append(f"\n{i}. {r['title']}")
                    output.append(f"URL: {r['url']}")
                    if r['snippet']:
                        output.append(f"{r['snippet'][:200]}")

        return [types.TextContent(type="text", text="\n".join(output))]

    return [types.TextContent(type="text", text=f"Unknown tool: {name}")]


async def main():
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())

if __name__ == "__main__":
    asyncio.run(main())

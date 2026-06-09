import asyncio
import json
import logging
import os
import sqlite3
from datetime import datetime

import aiosqlite
import httpx
from bs4 import BeautifulSoup
from mcp.server import Server
from mcp.server.sse import SseServerTransport
from mcp.types import TextContent, Tool
from starlette.applications import Starlette
from starlette.routing import Route
import uvicorn

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
log = logging.getLogger("dws-mcp")

DB_PATH   = os.getenv("DB_PATH", "/data/darkweb.db")
TOR_HOST  = os.getenv("TOR_SOCKS_HOST", "tor")
TOR_PORT  = int(os.getenv("TOR_SOCKS_PORT", "9050"))
PROXY_URL = f"socks5://{TOR_HOST}:{TOR_PORT}"

app = Server("dark-web-scraper")

async def init_db():
    async with aiosqlite.connect(DB_PATH) as db:
        await db.executescript("""
            CREATE TABLE IF NOT EXISTS pages (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                url       TEXT NOT NULL,
                html      TEXT,
                text      TEXT,
                fetched_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS entities (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                page_id   INTEGER REFERENCES pages(id),
                type      TEXT,
                value     TEXT,
                found_at  TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS monitors (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                url       TEXT UNIQUE NOT NULL,
                interval_minutes INTEGER DEFAULT 60,
                last_checked     TEXT,
                last_hash        TEXT,
                active    INTEGER DEFAULT 1
            );
            CREATE TABLE IF NOT EXISTS alerts (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                monitor_id INTEGER REFERENCES monitors(id),
                url       TEXT,
                message   TEXT,
                seen      INTEGER DEFAULT 0,
                created_at TEXT NOT NULL
            );
        """)
        await db.commit()
    log.info("DB מוכן")

async def fetch_onion(url: str) -> dict:
    try:
        async with httpx.AsyncClient(
            proxy=PROXY_URL,
            timeout=30,
            follow_redirects=True
        ) as client:
            r = await client.get(url)
            soup = BeautifulSoup(r.text, "html.parser")
            text = soup.get_text(separator="\n", strip=True)
            return {"url": url, "html": r.text, "text": text, "status": r.status_code}
    except Exception as e:
        return {"url": url, "error": str(e)}

import re

PATTERNS = {
    "ipv4":    r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    "onion":   r"\b[a-z2-7]{16,56}\.onion\b",
    "email":   r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
    "btc":     r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b",
    "cve":     r"CVE-\d{4}-\d{4,7}",
    "md5":     r"\b[a-fA-F0-9]{32}\b",
    "sha256":  r"\b[a-fA-F0-9]{64}\b",
}

def extract_entities(text: str) -> list:
    found = []
    for etype, pattern in PATTERNS.items():
        for match in re.finditer(pattern, text):
            found.append({"type": etype, "value": match.group()})
    return found


@app.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="scrape_page",
            description="מוריד דף .onion דרך Tor ומחזיר את התוכן",
            inputSchema={
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "כתובת .onion"}
                },
                "required": ["url"]
            }
        ),
        Tool(
            name="extract_entities",
            description="מחלץ IPs, emails, Bitcoin addresses, CVEs, hashes מטקסט",
            inputSchema={
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "כתובת .onion לסריקה"}
                },
                "required": ["url"]
            }
        ),
        Tool(
            name="search_index",
            description="חיפוש keyword או regex על דפים שנשמרו ב-DB",
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "מחרוזת חיפוש"}
                },
                "required": ["query"]
            }
        ),
        Tool(
            name="monitor_site",
            description="מוסיף אתר לניטור רציף על ידי הדאמון",
            inputSchema={
                "type": "object",
                "properties": {
                    "url":               {"type": "string"},
                    "interval_minutes":  {"type": "integer", "default": 60}
                },
                "required": ["url"]
            }
        ),
        Tool(
            name="get_alerts",
            description="מחזיר התראות שנאספו מאז החיבור האחרון",
            inputSchema={
                "type": "object",
                "properties": {}
            }
        ),
        Tool(
            name="daemon_status",
            description="מחזיר סטטוס הדאמון ומטרות פעילות",
            inputSchema={
                "type": "object",
                "properties": {}
            }
        ),
    ]

@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    await init_db()

    if name == "scrape_page":
        result = await fetch_onion(arguments["url"])
        if "error" in result:
            return [TextContent(type="text", text=f"שגיאה: {result['error']}")]
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute(
                "INSERT INTO pages (url, html, text, fetched_at) VALUES (?,?,?,?)",
                (result["url"], result["html"], result["text"],
                 datetime.utcnow().isoformat())
            )
            await db.commit()
        preview = result["text"][:2000]
        return [TextContent(type="text", text=f"נשמר בDB\n\n{preview}")]

    elif name == "extract_entities":
        result = await fetch_onion(arguments["url"])
        if "error" in result:
            return [TextContent(type="text", text=f"שגיאה: {result['error']}")]
        entities = extract_entities(result["text"])
        async with aiosqlite.connect(DB_PATH) as db:
            cur = await db.execute(
                "INSERT INTO pages (url, html, text, fetched_at) VALUES (?,?,?,?)",
                (result["url"], result["html"], result["text"],
                 datetime.utcnow().isoformat())
            )
            page_id = cur.lastrowid
            for e in entities:
                await db.execute(
                    "INSERT INTO entities (page_id, type, value, found_at) VALUES (?,?,?,?)",
                    (page_id, e["type"], e["value"], datetime.utcnow().isoformat())
                )
            await db.commit()
        summary = json.dumps(entities, ensure_ascii=False, indent=2)
        return [TextContent(type="text", text=f"נמצאו {len(entities)} entities:\n{summary}")]

    elif name == "search_index":
        q = arguments["query"]
        async with aiosqlite.connect(DB_PATH) as db:
            cur = await db.execute(
                "SELECT url, text, fetched_at FROM pages WHERE text LIKE ?",
                (f"%{q}%",)
            )
            rows = await cur.fetchall()
        if not rows:
            return [TextContent(type="text", text="לא נמצא תוצאות")]
        out = "\n\n".join(
            f"URL: {r[0]}\nזמן: {r[2]}\nקטע: ...{r[1][max(0,r[1].find(q)-100):r[1].find(q)+200]}..."
            for r in rows
        )
        return [TextContent(type="text", text=out)]

    elif name == "monitor_site":
        url      = arguments["url"]
        interval = arguments.get("interval_minutes", 60)
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute(
                """INSERT INTO monitors (url, interval_minutes)
                   VALUES (?,?)
                   ON CONFLICT(url) DO UPDATE SET
                   interval_minutes=excluded.interval_minutes, active=1""",
                (url, interval)
            )
            await db.commit()
        return [TextContent(type="text",
            text=f"מטרה נוספה: {url}\nסריקה כל {interval} דקות")]

    elif name == "get_alerts":
        async with aiosqlite.connect(DB_PATH) as db:
            cur = await db.execute(
                "SELECT url, message, created_at FROM alerts WHERE seen=0 ORDER BY created_at DESC"
            )
            rows = await cur.fetchall()
            await db.execute("UPDATE alerts SET seen=1")
            await db.commit()
        if not rows:
            return [TextContent(type="text", text="אין התראות חדשות")]
        out = "\n\n".join(f"[{r[2]}] {r[0]}\n{r[1]}" for r in rows)
        return [TextContent(type="text", text=out)]

    elif name == "daemon_status":
        async with aiosqlite.connect(DB_PATH) as db:
            cur = await db.execute(
                "SELECT url, interval_minutes, last_checked, active FROM monitors"
            )
            rows = await cur.fetchall()
        if not rows:
            return [TextContent(type="text", text="אין מטרות מוגדרות עדיין")]
        out = "\n".join(
            f"{'✓' if r[3] else '✗'} {r[0]} | כל {r[1]} דקות | נבדק: {r[2] or 'אף פעם'}"
            for r in rows
        )
        return [TextContent(type="text", text=out)]

    return [TextContent(type="text", text=f"tool לא מוכר: {name}")]



async def main():
    await init_db()
    mode = os.getenv("MCP_MODE", "sse")

    if mode == "stdio":
        from mcp.server.stdio import stdio_server
        async with stdio_server() as (read_stream, write_stream):
            await app.run(read_stream, write_stream, app.create_initialization_options())
    else:
        from mcp.server.sse import SseServerTransport
        from starlette.applications import Starlette
        from starlette.routing import Route
        from starlette.responses import JSONResponse
        import uvicorn

        sse = SseServerTransport("/messages")

        async def handle_sse(request):
            async with sse.connect_sse(request.scope, request.receive, request._send) as streams:
                await app.run(streams[0], streams[1], app.create_initialization_options())

        async def health(request):
            return JSONResponse({"status": "ok"})

        starlette_app = Starlette(routes=[
            Route("/sse", handle_sse),
            Route("/health", health),
            Route("/messages", sse.handle_post_message, methods=["POST"]),
        ])

        config = uvicorn.Config(starlette_app, host="0.0.0.0", port=8765, log_level="info")
        server = uvicorn.Server(config)
        await server.serve()

if __name__ == "__main__":
    asyncio.run(main())

import asyncio
import hashlib
import logging
import os
from datetime import datetime

import aiosqlite
import httpx
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from bs4 import BeautifulSoup

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
log = logging.getLogger("dws-daemon")

DB_PATH          = os.getenv("DB_PATH", "/data/darkweb.db")
TOR_HOST         = os.getenv("TOR_SOCKS_HOST", "tor")
TOR_PORT         = int(os.getenv("TOR_SOCKS_PORT", "9050"))
PROXY_URL        = f"socks5://{TOR_HOST}:{TOR_PORT}"
SCAN_INTERVAL    = int(os.getenv("SCAN_INTERVAL_MINUTES", "60"))

async def fetch(url: str) -> dict:
    try:
        async with httpx.AsyncClient(
            proxy=PROXY_URL,
            timeout=30,
            follow_redirects=True
        ) as client:
            r = await client.get(url)
            soup = BeautifulSoup(r.text, "html.parser")
            text = soup.get_text(separator="\n", strip=True)
            h    = hashlib.sha256(text.encode()).hexdigest()
            return {"url": url, "text": text, "hash": h}
    except Exception as e:
        log.warning(f"fetch failed {url}: {e}")
        return {"url": url, "error": str(e)}

async def scan_monitors():
    log.info(f"סריקה — {datetime.utcnow().isoformat()}")
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(
            "SELECT id, url, last_hash FROM monitors WHERE active=1"
        )
        targets = await cur.fetchall()

    for monitor_id, url, last_hash in targets:
        result = await fetch(url)
        now = datetime.utcnow().isoformat()

        if "error" in result:
            continue

        new_hash = result["hash"]
        changed  = last_hash and last_hash != new_hash

        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute(
                "UPDATE monitors SET last_checked=?, last_hash=? WHERE id=?",
                (now, new_hash, monitor_id)
            )
            await db.execute(
                "INSERT INTO pages (url, text, fetched_at) VALUES (?,?,?)",
                (url, result["text"], now)
            )
            if changed:
                log.info(f"שינוי זוהה: {url}")
                await db.execute(
                    "INSERT INTO alerts (monitor_id, url, message, created_at) VALUES (?,?,?,?)",
                    (monitor_id, url, f"תוכן השתנה ב-{now}", now)
                )
            await db.commit()

async def main():
    log.info(f"Daemon מתחיל — סריקה כל {SCAN_INTERVAL} דקות")
    scheduler = AsyncIOScheduler()
    scheduler.add_job(
        scan_monitors,
        trigger="interval",
        minutes=SCAN_INTERVAL,
        next_run_time=datetime.utcnow()
    )
    scheduler.start()
    try:
        while True:
            await asyncio.sleep(60)
    except (KeyboardInterrupt, SystemExit):
        scheduler.shutdown()

if __name__ == "__main__":
    asyncio.run(main())

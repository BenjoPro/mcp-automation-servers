import sqlite3
import json
from datetime import datetime
from pathlib import Path

DB_PATH = Path("/data/mempalace.db")


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_connection()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS campaigns (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            target TEXT NOT NULL,
            objective TEXT,
            tools_used TEXT,
            findings TEXT,
            patterns TEXT,
            tags TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE VIRTUAL TABLE IF NOT EXISTS campaigns_fts
        USING fts5(name, target, objective, findings, patterns, tags, content=campaigns, content_rowid=id)
    """)
    conn.execute("""
        CREATE TRIGGER IF NOT EXISTS campaigns_ai AFTER INSERT ON campaigns BEGIN
            INSERT INTO campaigns_fts(rowid, name, target, objective, findings, patterns, tags)
            VALUES (new.id, new.name, new.target, new.objective, new.findings, new.patterns, new.tags);
        END
    """)
    conn.commit()
    conn.close()


def save_campaign(name: str, target: str, objective: str, tools_used: list, findings: str, patterns: str, tags: list) -> dict:
    conn = get_connection()
    now = datetime.utcnow().isoformat()
    cursor = conn.execute(
        """INSERT INTO campaigns (name, target, objective, tools_used, findings, patterns, tags, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (name, target, objective, json.dumps(tools_used), findings, patterns, json.dumps(tags), now, now)
    )
    conn.commit()
    campaign_id = cursor.lastrowid
    conn.close()
    return {"id": campaign_id, "name": name, "created_at": now}


def get_campaign(campaign_id: int) -> dict | None:
    conn = get_connection()
    row = conn.execute("SELECT * FROM campaigns WHERE id = ?", (campaign_id,)).fetchone()
    conn.close()
    if not row:
        return None
    return _row_to_dict(row)


def list_campaigns() -> list:
    conn = get_connection()
    rows = conn.execute("SELECT * FROM campaigns ORDER BY created_at DESC").fetchall()
    conn.close()
    return [_row_to_dict(r) for r in rows]


def search_campaigns(query: str) -> list:
    conn = get_connection()
    rows = conn.execute(
        """SELECT campaigns.* FROM campaigns
           JOIN campaigns_fts ON campaigns.id = campaigns_fts.rowid
           WHERE campaigns_fts MATCH ?
           ORDER BY rank""",
        (query,)
    ).fetchall()
    conn.close()
    return [_row_to_dict(r) for r in rows]


def get_patterns() -> dict:
    conn = get_connection()
    rows = conn.execute("SELECT tools_used, tags, patterns FROM campaigns").fetchall()
    conn.close()

    tool_counts = {}
    tag_counts = {}
    all_patterns = []

    for row in rows:
        for tool in json.loads(row["tools_used"] or "[]"):
            tool_counts[tool] = tool_counts.get(tool, 0) + 1
        for tag in json.loads(row["tags"] or "[]"):
            tag_counts[tag] = tag_counts.get(tag, 0) + 1
        if row["patterns"]:
            all_patterns.append(row["patterns"])

    return {
        "total_campaigns": len(rows),
        "top_tools": sorted(tool_counts.items(), key=lambda x: x[1], reverse=True)[:10],
        "top_tags": sorted(tag_counts.items(), key=lambda x: x[1], reverse=True)[:10],
        "patterns_summary": all_patterns
    }


def _row_to_dict(row) -> dict:
    d = dict(row)
    d["tools_used"] = json.loads(d.get("tools_used") or "[]")
    d["tags"] = json.loads(d.get("tags") or "[]")
    return d

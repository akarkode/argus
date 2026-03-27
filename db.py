import aiosqlite
import json
import os
import time

from dotenv import load_dotenv

load_dotenv()

DB_PATH = os.getenv("DB_PATH", "sara.db")


async def init_db():
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id          TEXT PRIMARY KEY,
                domain      TEXT NOT NULL,
                status      TEXT NOT NULL DEFAULT 'queued',
                tools       TEXT NOT NULL DEFAULT '[]',
                wordlist    TEXT DEFAULT 'default',
                created_at  REAL NOT NULL,
                finished_at REAL
            )
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS results (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id  TEXT NOT NULL,
                tool     TEXT NOT NULL,
                line     TEXT NOT NULL,
                data     TEXT DEFAULT '{}',
                ts       REAL NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            )
        """)
        await db.execute(
            "CREATE INDEX IF NOT EXISTS idx_results_scan ON results(scan_id)"
        )
        await db.execute(
            "CREATE INDEX IF NOT EXISTS idx_results_tool ON results(scan_id, tool)"
        )
        await db.commit()


async def create_scan(
    scan_id: str, domain: str, tools: list[str], wordlist: str = "default"
) -> dict:
    now = time.time()
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT INTO scans (id, domain, status, tools, wordlist, created_at) "
            "VALUES (?, ?, 'queued', ?, ?, ?)",
            (scan_id, domain, json.dumps(tools), wordlist, now),
        )
        await db.commit()
    return {
        "id": scan_id, "domain": domain, "status": "queued",
        "tools": tools, "created_at": now,
    }


async def update_scan_status(scan_id: str, status: str):
    async with aiosqlite.connect(DB_PATH) as db:
        if status in ("completed", "error", "timeout"):
            await db.execute(
                "UPDATE scans SET status = ?, finished_at = ? WHERE id = ?",
                (status, time.time(), scan_id),
            )
        else:
            await db.execute(
                "UPDATE scans SET status = ? WHERE id = ?",
                (status, scan_id),
            )
        await db.commit()


async def insert_result(
    scan_id: str, tool: str, line: str, data: dict | None = None
) -> dict:
    ts = time.time()
    payload = json.dumps(data) if data else "{}"
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT INTO results (scan_id, tool, line, data, ts) VALUES (?, ?, ?, ?, ?)",
            (scan_id, tool, line, payload, ts),
        )
        await db.commit()
    return {"tool": tool, "line": line, "data": data or {}, "ts": ts}


async def get_scan(scan_id: str) -> dict | None:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
        row = await cur.fetchone()
        if not row:
            return None
        scan = dict(row)
        scan["tools"] = json.loads(scan.get("tools", "[]"))
        return scan


async def get_scan_results(
    scan_id: str,
    tools: list[str] | None = None,
    status_codes: list[int] | None = None,
) -> list[dict]:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        query = "SELECT tool, line, data, ts FROM results WHERE scan_id = ?"
        params: list = [scan_id]

        if tools:
            placeholders = ",".join("?" * len(tools))
            query += f" AND tool IN ({placeholders})"
            params.extend(tools)

        query += " ORDER BY ts ASC"
        cur = await db.execute(query, params)
        rows = await cur.fetchall()

        out = []
        for r in rows:
            entry = dict(r)
            try:
                entry["data"] = json.loads(entry.get("data", "{}"))
            except (json.JSONDecodeError, TypeError):
                entry["data"] = {}

            if status_codes and entry["data"].get("status_code"):
                if entry["data"]["status_code"] not in status_codes:
                    continue

            out.append(entry)
        return out


async def get_all_scans(limit: int = 50, offset: int = 0) -> list[dict]:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            "SELECT * FROM scans ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (limit, offset),
        )
        rows = await cur.fetchall()
        out = []
        for r in rows:
            scan = dict(r)
            scan["tools"] = json.loads(scan.get("tools", "[]"))
            out.append(scan)
        return out

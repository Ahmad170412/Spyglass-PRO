"""SQLite case store for scan persistence and history."""

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

STORE_DIR = Path.home() / ".lens-extender"
STORE_FILE = STORE_DIR / "cases.db"


def _get_conn() -> sqlite3.Connection:
    STORE_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(STORE_FILE))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            scan_type TEXT DEFAULT 'passive',
            timestamp TEXT NOT NULL,
            data_json TEXT NOT NULL,
            errors TEXT DEFAULT ''
        )
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target)
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans(timestamp)
    """)
    conn.commit()
    return conn


def store_scan(target: str, report: dict, scan_type: str = "passive") -> bool:
    """Store a scan result. Returns True on success."""
    conn = None
    try:
        conn = _get_conn()
        conn.execute(
            "INSERT INTO scans (target, scan_type, timestamp, data_json, errors) VALUES (?, ?, ?, ?, ?)",
            (
                target,
                scan_type,
                datetime.now(timezone.utc).isoformat(),
                json.dumps(report, default=str, ensure_ascii=False),
                json.dumps(report.get("errors", [])),
            ),
        )
        conn.commit()
        return True
    except Exception:
        return False
    finally:
        if conn is not None:
            conn.close()


def list_targets() -> list[dict]:
    """List all stored targets with scan counts and latest timestamp."""
    conn = None
    try:
        conn = _get_conn()
        rows = conn.execute("""
            SELECT target, COUNT(*) as scan_count, MAX(timestamp) as last_scan
            FROM scans
            GROUP BY target
            ORDER BY last_scan DESC
        """).fetchall()
        return [
            {
                "target": r["target"],
                "scan_count": r["scan_count"],
                "last_scan": r["last_scan"],
            }
            for r in rows
        ]
    except Exception:
        return []
    finally:
        if conn is not None:
            conn.close()


def get_scans(target: str) -> list[dict]:
    """Get all scans for a target."""
    conn = None
    try:
        conn = _get_conn()
        rows = conn.execute(
            "SELECT id, scan_type, timestamp, data_json, errors FROM scans WHERE target = ? ORDER BY timestamp DESC",
            (target,),
        ).fetchall()
        results = []
        for r in rows:
            results.append(
                {
                    "id": r["id"],
                    "scan_type": r["scan_type"],
                    "timestamp": r["timestamp"],
                    "data": json.loads(r["data_json"]),
                }
            )
        return results
    except Exception:
        return []
    finally:
        if conn is not None:
            conn.close()


def diff_scans(target: str) -> dict | None:
    """Compare the two most recent scans for a target."""
    scans = get_scans(target)
    if len(scans) < 2:
        return None
    older = scans[1]["data"]
    newer = scans[0]["data"]
    changes: dict[str, dict | str] = {}
    older_ports = {p["port"] for p in older.get("ports", [])}
    newer_ports = {p["port"] for p in newer.get("ports", [])}
    added = newer_ports - older_ports
    removed = older_ports - newer_ports
    if added or removed:
        changes["ports"] = {"added": sorted(added), "removed": sorted(removed)}
    older_vulns = {v["id"] for v in older.get("vulns", [])}
    newer_vulns = {v["id"] for v in newer.get("vulns", [])}
    added_v = newer_vulns - older_vulns
    removed_v = older_vulns - newer_vulns
    if added_v or removed_v:
        changes["vulns"] = {"added": sorted(added_v), "removed": sorted(removed_v)}
    older_certs = len(older.get("certs", []))
    newer_certs = len(newer.get("certs", []))
    if newer_certs != older_certs:
        changes["certs"] = {"old_count": older_certs, "new_count": newer_certs}
    return changes if changes else {"message": "No changes detected"}


def get_timeline(target: str) -> list[dict]:
    """Get scan timestamps for a target."""
    scans = get_scans(target)
    return [{"timestamp": s["timestamp"], "scan_type": s["scan_type"], "id": s["id"]} for s in scans]

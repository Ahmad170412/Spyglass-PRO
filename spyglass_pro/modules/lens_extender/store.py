"""SQLite case store — the surviving half of Lens-Extender.

Lens-Extender's recon engine was deleted in the 2026-10 cleanup. What
remains is the table handle, so runs written by an older build can still
be listed and deleted by the merge layer (``spyglass_pro.runner``). Every
upstream helper that went with the engine — the scan writer, the
port/vuln diff, the target and timeline readers — is gone: nothing in
this build can create a Lens run, only clean up an old one.
"""

import sqlite3
from pathlib import Path

STORE_DIR = Path.home() / ".lens-extender"
STORE_FILE = STORE_DIR / "cases.db"


def _get_conn() -> sqlite3.Connection:
    STORE_DIR.mkdir(parents=True, exist_ok=True)
    # 30s lock timeout + WAL: a reader must wait for another process rather
    # than fail at sqlite3's 5s default, and WAL keeps reads non-blocking.
    conn = sqlite3.connect(str(STORE_FILE), timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=30000")
    # Idempotent: a legacy database already has this schema (no-op), and a
    # fresh file gets the same shape so the queries below always bind.
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

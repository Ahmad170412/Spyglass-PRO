"""Durable social targets and per-check snapshots — the memory behind CHECK AGAIN.

A target is a (platform, handle) pair added once on the Targets page; the
social tabs never configure a target again, they only *check* it. Every
successful check appends one snapshot row; the diff engine reads the two
most recent snapshots to describe what changed, and the history rail
renders one card per retained check.

Design rules, inherited from GREENWICH's hard-won lessons:

* **One database, one key, one path.** Snapshots live in the same
  ``spyglass.db`` as the case store and reuse its connection, its Fernet
  encryption and its ``SPYGLASS_HOME`` — deleting the store deletes
  everything, exactly once.
* **A failed run is not a check.** :func:`record_check` with an error
  status updates the target's bookkeeping (``last_status`` /
  ``last_check_at``) but never writes a snapshot, so a network blip can
  never overwrite a good baseline or pollute the diff chain.
* **The baseline survives retention.** The last ``HISTORY_LIMIT = 20``
  snapshots are kept per target (pruned in the same transaction as the
  insert); the *baseline* — first successful check's timestamp and
  counts — lives on the target row itself, so the history rail can always
  show where tracking began even after 20 more checks have scrolled past.
* **One ordered query serves every view** (GREENWICH's same-order
  invariant): history, latest and stat deltas all read
  ``ORDER BY taken_at DESC, id DESC`` — two differently-ordered reads of
  the same rows are how "diffed" lists invent hundreds of changes.

Handles are normalized once, here: stripped of whitespace and any
leading ``@``, lowercased. All six platforms resolve handles
case-insensitively, so ``@Dawn`` and ``dawn`` must be one target, not
two — the UNIQUE constraint enforces it after normalization.

Removal deletes snapshots explicitly rather than trusting the
``ON DELETE CASCADE`` in the DDL: SQLite foreign keys are OFF by default
per connection, so relying on the cascade would leave orphaned snapshot
rows — target data — on disk after the operator asked to forget it.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime
from typing import Any

# Same path dance as runner.py: the vendored engines import each other as
# top-level packages, so modules/ must be importable before store resolves.
MODULES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "modules")
if MODULES_DIR not in sys.path:
    sys.path.insert(0, MODULES_DIR)

from spyglass_osint import store as _store  # noqa: E402

# Retention: last 20 checks per target, enforced in the insert transaction.
HISTORY_LIMIT = 20

# Statuses that count as a check worth remembering. "partial" keeps its
# snapshot because the payload carries per-list completeness flags — the
# diff engine, not the writer, decides what may be compared.
_OK_STATUSES = ("ok", "partial")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS social_targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    platform TEXT NOT NULL,
    handle TEXT NOT NULL,
    native_id TEXT,
    created_at TEXT NOT NULL,
    baseline_at TEXT,
    baseline_json TEXT,
    last_check_at TEXT,
    checks INTEGER NOT NULL DEFAULT 0,
    last_status TEXT,
    UNIQUE(platform, handle)
);
CREATE TABLE IF NOT EXISTS social_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER NOT NULL REFERENCES social_targets(id) ON DELETE CASCADE,
    taken_at TEXT NOT NULL,
    payload TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_snapshots_target
    ON social_snapshots(target_id, taken_at DESC);
"""


def _init(db) -> None:
    db.executescript(_SCHEMA)
    db.commit()


def _now() -> str:
    # Local wall clock, second precision — same shape as the case store's
    # run_at, so every timestamp in SPYGLASS_HOME sorts together.
    return datetime.now().isoformat(timespec="seconds")


def _norm(platform: str, handle: str) -> tuple[str, str]:
    """Normalize one target identity. Raises ValueError when unusable."""
    p = (platform or "").strip().lower()
    h = (handle or "").strip().lstrip("@").strip().lower()
    if not p or not h:
        raise ValueError("platform and handle are both required")
    if len(p) > 64:
        raise ValueError(f"platform {platform!r} is too long")
    if len(h) > 255 or any(c.isspace() for c in h):
        raise ValueError(f"handle {handle!r} is not a valid handle")
    return p, h


def _row(r) -> dict[str, Any]:
    """One target row as a dict, baseline decrypted and parsed."""
    d = dict(r)
    raw = d.pop("baseline_json", None)
    d["baseline"] = json.loads(_store._decrypt(raw)) if raw else None
    return d


def _target_row(db, target_id: int) -> dict[str, Any]:
    row = db.execute("SELECT * FROM social_targets WHERE id=?", (target_id,)).fetchone()
    if row is None:
        raise ValueError(f"no target #{target_id}")
    return _row(row)


def _prune(db, target_id: int) -> None:
    """Keep the newest HISTORY_LIMIT snapshots. Runs inside the write txn."""
    db.execute(
        "DELETE FROM social_snapshots WHERE target_id=? AND id NOT IN ("
        "SELECT id FROM social_snapshots WHERE target_id=? "
        "ORDER BY taken_at DESC, id DESC LIMIT ?)",
        (target_id, target_id, HISTORY_LIMIT),
    )


# ─── targets ─────────────────────────────────────────────


def add_target(platform: str, handle: str, native_id: str | None = None) -> dict[str, Any]:
    """Register a target. Raises ValueError on duplicates or bad input."""
    p, h = _norm(platform, handle)
    db = _store._connect()
    try:
        _init(db)
        dup = db.execute(
            "SELECT id FROM social_targets WHERE platform=? AND handle=?", (p, h)
        ).fetchone()
        if dup:
            raise ValueError(f"{h} on {p} is already tracked")
        cur = db.execute(
            "INSERT INTO social_targets (platform, handle, native_id, created_at) "
            "VALUES (?, ?, ?, ?)",
            (p, h, native_id or None, _now()),
        )
        db.commit()
        return _target_row(db, cur.lastrowid)
    finally:
        db.close()


def list_targets() -> list[dict[str, Any]]:
    """Every tracked target, stable order (platform, handle)."""
    db = _store._connect()
    try:
        _init(db)
        rows = db.execute(
            "SELECT * FROM social_targets ORDER BY platform, handle"
        ).fetchall()
        return [_row(r) for r in rows]
    finally:
        db.close()


def get_target(target_id: int) -> dict[str, Any] | None:
    db = _store._connect()
    try:
        _init(db)
        row = db.execute("SELECT * FROM social_targets WHERE id=?", (target_id,)).fetchone()
        return _row(row) if row else None
    finally:
        db.close()


def find_target(platform: str, handle: str) -> dict[str, Any] | None:
    """Look a target up by identity (normalized the same way as add)."""
    try:
        p, h = _norm(platform, handle)
    except ValueError:
        return None
    db = _store._connect()
    try:
        _init(db)
        row = db.execute(
            "SELECT * FROM social_targets WHERE platform=? AND handle=?", (p, h)
        ).fetchone()
        return _row(row) if row else None
    finally:
        db.close()


def remove_target(target_id: int) -> bool:
    """Forget a target and every snapshot it owns. True if it existed."""
    db = _store._connect()
    try:
        _init(db)
        exists = db.execute(
            "SELECT 1 FROM social_targets WHERE id=?", (target_id,)
        ).fetchone()
        if not exists:
            return False
        # Explicit, not cascade — foreign_keys is OFF by default (module docstring).
        db.execute("DELETE FROM social_snapshots WHERE target_id=?", (target_id,))
        db.execute("DELETE FROM social_targets WHERE id=?", (target_id,))
        db.commit()
        return True
    finally:
        db.close()


# ─── snapshots ───────────────────────────────────────────


def record_check(
    target_id: int,
    payload: dict[str, Any] | None = None,
    status: str = "ok",
    error: str | None = None,
    native_id: str | None = None,
) -> dict[str, Any]:
    """Book one check and return the updated target.

    ``status`` in ``("ok", "partial")`` with a payload appends a snapshot,
    bumps ``checks`` and — on the first check — pins the baseline to this
    payload. Anything else is a failed run: bookkeeping only, never a
    snapshot, so a blip cannot overwrite the chain the diff engine reads.

    The stored payload records its own ``status`` (``ok``/``partial``) so
    the diff engine can treat a partial run honestly without a second query.
    """
    db = _store._connect()
    try:
        _init(db)
        row = db.execute(
            "SELECT * FROM social_targets WHERE id=?", (target_id,)
        ).fetchone()
        if row is None:
            raise ValueError(f"no target #{target_id}")
        now = _now()

        if status in _OK_STATUSES and payload is not None:
            stored = dict(payload)
            stored["status"] = status
            blob = _store._encrypt(json.dumps(stored, default=str))
            db.execute(
                "INSERT INTO social_snapshots (target_id, taken_at, payload) "
                "VALUES (?, ?, ?)",
                (target_id, now, blob),
            )
            if not row["baseline_at"]:
                db.execute(
                    "UPDATE social_targets SET baseline_at=?, baseline_json=? "
                    "WHERE id=?",
                    (now, blob, target_id),
                )
            db.execute(
                "UPDATE social_targets SET checks=checks+1, last_check_at=?, "
                "last_status=?, native_id=COALESCE(NULLIF(?, ''), native_id) "
                "WHERE id=?",
                (now, status, native_id, target_id),
            )
            _prune(db, target_id)
        else:
            # Failed run: bookkeeping only. last_status carries the reason.
            db.execute(
                "UPDATE social_targets SET last_check_at=?, last_status=?, "
                "native_id=COALESCE(NULLIF(?, ''), native_id) WHERE id=?",
                (now, str(error or status)[:300], native_id, target_id),
            )
        db.commit()
        return _target_row(db, target_id)
    finally:
        db.close()


def history(target_id: int, limit: int = HISTORY_LIMIT) -> list[dict[str, Any]]:
    """Newest-first snapshot history: ``[{taken_at, payload}, ...]``.

    One query, one order — history cards, stat deltas and the diff engine
    all read the chain exactly this way.
    """
    db = _store._connect()
    try:
        _init(db)
        rows = db.execute(
            "SELECT taken_at, payload FROM social_snapshots "
            "WHERE target_id=? ORDER BY taken_at DESC, id DESC LIMIT ?",
            (target_id, limit),
        ).fetchall()
        return [
            {"taken_at": r["taken_at"],
             "payload": json.loads(_store._decrypt(r["payload"]))}
            for r in rows
        ]
    finally:
        db.close()


def latest_snapshot(target_id: int) -> dict[str, Any] | None:
    """The most recent successful payload — the diff base. None if unchecked."""
    hist = history(target_id, limit=1)
    return hist[0]["payload"] if hist else None

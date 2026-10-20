"""The dashboard's outbound credential vault.

This used to be ``lens_extender.config`` — the vendored Lens engine's own
config file. That coupling was invisible until the day someone cuts Lens
out of this tree: Settings would have lost its storage backend and every
saved API key with it. The vault therefore owns its own file now, under
``~/.spyglass/vault.json``, and has no import edge to any vendored engine.

Operator data is not thrown away in the move. The first time the vault
runs and finds no vault file, it looks for the old Lens config once,
carries over the keys this build still uses, and writes them to the new
file. The old file is read-only in that transaction: it is never
rewritten and never deleted, because the sibling tool still owns it.

The file is written 0600 on POSIX (Windows has no POSIX mode bits, so the
chmod is skipped there, exactly as the old implementation did).
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

VAULT_DIR = Path.home() / ".spyglass"
VAULT_FILE = VAULT_DIR / "vault.json"

# The old home of these values — Lens-Extender's config file. Read once at
# migration time, never written, never deleted.
LEGACY_FILE = Path.home() / ".lens-extender" / "config.json"

# The only keys this build stores. Everything else the legacy config
# held belonged to the dormant IP/Lens infrastructure and is left there.
KEYS = ("intelx_api_key", "hibp_api_key", "proxy", "socks_proxy")


def _tighten(path: Path) -> None:
    """Best-effort 0600 on the vault file (no-op on Windows)."""
    if sys.platform == "win32":
        return
    try:
        path.chmod(0o600)
    except OSError:
        pass


def _read(path: Path):
    """Parsed JSON from ``path``, or None when it is missing/unreadable."""
    try:
        if not path.exists():
            return None
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _migrate():
    """Carry the legacy Lens config over once, on first run."""
    legacy = _read(LEGACY_FILE)
    if not isinstance(legacy, dict):
        return {}
    carried = {key: legacy[key] for key in KEYS
               if isinstance(legacy.get(key), str) and legacy.get(key)}
    if carried:
        save(carried)
    return carried


def load() -> dict:
    """Stored values for :data:`KEYS` (empty strings for unset keys)."""
    data = _read(VAULT_FILE)
    if data is None:
        data = _migrate()
    if not isinstance(data, dict):
        return {}
    return {key: str(data.get(key) or "") for key in KEYS}


def save(config: dict) -> None:
    """Write ``config`` to the vault file, keeping only :data:`KEYS`."""
    values = {key: str((config or {}).get(key) or "") for key in KEYS}
    VAULT_DIR.mkdir(parents=True, exist_ok=True)
    # os.open carries the 0600 mode at creation time, so the file is never
    # briefly world-readable between create and chmod.
    fd = os.open(VAULT_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    # encoding is explicit: an API key or proxy with a non-ASCII character
    # must not fail on a cp1252 default install (Windows).
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(json.dumps(values, indent=2))
    _tighten(VAULT_FILE)

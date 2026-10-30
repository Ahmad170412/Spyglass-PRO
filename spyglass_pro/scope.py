"""The recon vocabulary this build exposes.

This is a HUMINT build. The IP module, the heavy website phases and
Lens-Extender were **deleted** in the 2026-10 cleanup — no longer merely
unexposed. What remains in ``spyglass_pro/modules/`` is either exposed
here or has no product surface at all: the only survivor with no surface
is Lens-Extender's SQLite case store, which exists so runs written by an
older build can still be listed and deleted. It cannot collect anything.

Everything reachable by an operator is listed here. The point is that
"what this build does" is one reviewable list instead of a handler map
plus a UI grid plus a docs page that can drift apart. The list is
enforced, not decorative: ``app.py`` refuses any module that is not in
``EXPOSED_MODULES``, so a new engine cannot become reachable by accident.
"""

from __future__ import annotations

# Query types the dashboard and /api/spyglass/run accept.
EXPOSED_MODULES = (
    "email",
    "username",
    "phone",
    "website",
    "darkweb",
    "metadata",
    "opsec",
)

# The website phases this build promises. Everything heavier (ports,
# headers, subdomain enumeration, Shodan) was deleted with the rest of
# the infra work.
WEBSITE_LIGHT = ("registrant", "whois", "dns", "ct")


def is_exposed_module(name: str) -> bool:
    """True when a query type is reachable from the product surface."""
    return (name or "").strip().lower() in EXPOSED_MODULES

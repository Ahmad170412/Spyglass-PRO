"""The recon vocabulary this build exposes.

1.3 is a HUMINT release. The IP module, the heavy website phases and
Lens-Extender stay in the tree — the sibling tool consumes them — but
they are not part of the product surface: nothing in the dashboard or
the public API can reach them.

Everything reachable by an operator is listed here. The point is that
"what this build does" is one reviewable list instead of a handler map
plus a UI grid plus a docs page that can drift apart.

Dormant is not deleted. ``runner.run_spyglass`` still dispatches the
``ip`` handler for in-process callers and tests; the HTTP boundary in
``app.py`` is what refuses it. That keeps the vendored engine intact
while the product stops advertising it.
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

# Code that stays importable but has no product surface.
DORMANT_MODULES = ("ip",)
DORMANT_ENGINES = ("lens",)

# The website phases 1.3 promises. Everything heavier (ports, headers,
# subdomain enumeration, Shodan) is dormant with the rest of the infra
# work.
WEBSITE_LIGHT = ("registrant", "whois", "dns", "ct")


def is_exposed_module(name: str) -> bool:
    """True when a query type is reachable from the product surface."""
    return (name or "").strip().lower() in EXPOSED_MODULES


def is_dormant_module(name: str) -> bool:
    """True for modules kept in-tree but refused at the API boundary."""
    return (name or "").strip().lower() in DORMANT_MODULES


def is_dormant_engine(name: str) -> bool:
    """True for engines kept in-tree but refused at the API boundary."""
    return (name or "").strip().lower() in DORMANT_ENGINES


def dormant_error(kind: str, name: str) -> str:
    """The one wording every surface uses when something is unexposed."""
    return (f"{kind} {name!r} is dormant in this build and not exposed "
            "— see spyglass_pro/scope.py")

"""Keybase adapter — keyless collection over the public lookup API.

``keybase.io/_/api/1.0/user/lookup.json`` serves a profile and — the reason
this adapter exists — the account's **cryptographically-proven identity
proofs**: the Twitter, GitHub, Reddit, Hacker News, DNS and website accounts
the user has signed for with their Keybase key. That is *proven* cross-platform
correlation, not a guess from a shared handle, which is exactly the kind of
finding a passive investigation is for.

Be honest about the shape, though. The lookup returns a profile (full name,
location, bio, avatar, account-creation time) and the proof list, but **no
follower/following counts and no post list** — Keybase does not expose them
here — so those are neither promised in capabilities nor fabricated.

What it *does* carry that nothing else in the tree does: the proofs
(``proofs_summary.all``), each with a canonical ``service_url``, and any
on-file cryptocurrency addresses. Only proofs in the proven state are counted
as identity links; a pending or revoked proof is reported as a count, never
folded into the verified set — "we could not confirm this" and "this is
proven" must not look the same.

Unknown handles: the API answers ``{"them": [null]}`` for a name that passes
its own format check, so "no such user" is exact. A name that fails that
check comes back ``INPUT_ERROR``; handles are validated locally first, so a
typo never spends a request.

Username validation: 2-16 characters, letters/digits/underscore, not starting
with a separator (Keybase's own rule). Keybase usernames are lower-case.
"""

from __future__ import annotations

import re as _re
from datetime import datetime, timezone

import httpx

from .. import registry
from ..schema import add_note, add_wall, set_fields

CAPABILITIES = (
    "profile", "bio", "location", "joined", "avatar", "links",
    "identity proofs", "crypto addresses",
)

API = "https://keybase.io/_/api/1.0/user/lookup.json"

_TIMEOUT = 20.0
# The subset of the (large) user object this adapter needs. Requesting fields
# explicitly keeps the payload small; Keybase returns far more by default.
_FIELDS = "basics,profile,proofs_summary,pictures"

# 2-16 chars, letters/digits/underscore, may not start with a separator.
# Enforced locally so a malformed target fails cheaply instead of earning an
# INPUT_ERROR that looks like a real answer.
_LOGIN_RE = _re.compile(r"^[A-Za-z0-9][A-Za-z0-9_]{1,15}$")

# proof_type -> canonical URL. ``service_url`` is preferred when present;
# this is the fallback for proofs that carry a nametag but no service_url.
_PROOF_URLS = {
    "twitter": "https://twitter.com/{n}",
    "github": "https://github.com/{n}",
    "reddit": "https://reddit.com/user/{n}",
    "hackernews": "https://news.ycombinator.com/user?id={n}",
    "dns": "https://{n}",
    "generic_web_site": "https://{n}",
    "https": "https://{n}",
}

_WS_RE = _re.compile(r"\s+")


def _text(value) -> str:
    return _WS_RE.sub(" ", str(value or "")).strip()


def _avatar(profile: dict) -> str | None:
    primary = ((profile.get("pictures") or {}).get("primary")) or {}
    return primary.get("url") or None


def _iso(ctime) -> str | None:
    """Keybase account-creation time is epoch seconds → the ISO shape the
    other adapters use (GitHub emits ``...T..:..:..Z``)."""
    try:
        ts = int(ctime)
    except (TypeError, ValueError):
        return None
    if ts <= 0:
        return None
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _proof_list(profile: dict) -> list:
    proofs = ((profile.get("proofs_summary") or {}).get("all")) or []
    return [p for p in proofs if isinstance(p, dict)]


def _proof_link(proof: dict) -> str | None:
    """A canonical, clickable URL for one proof, or None if it has none.

    ``service_url`` is Keybase's own canonical link and is preferred; the
    per-type template is the fallback. A proof with neither a usable URL nor
    a known type still resolves to ``type:nametag`` so it is never silently
    dropped from the list.
    """
    service = _text(proof.get("service_url"))
    if service.startswith("http"):
        return service
    ptype = _text(proof.get("proof_type")).lower()
    name = _text(proof.get("nametag"))
    if not name:
        return None
    template = _PROOF_URLS.get(ptype)
    if template:
        return template.format(n=name)
    if name.startswith("http"):
        return name
    return f"{ptype}:{name}" if ptype else name


def normalize(profile: dict, result: dict) -> None:
    """Map a Keybase user object onto the normalized schema. Pure, offline."""
    if not isinstance(profile, dict):
        return
    basics = profile.get("basics") or {}
    username = _text(basics.get("username"))
    if not username:
        return
    result["found"] = True
    prof = profile.get("profile") or {}
    set_fields(
        result,
        display_name=_text(prof.get("full_name")) or username,
        bio=_text(prof.get("bio")),
        location=_text(prof.get("location")),
        url=f"https://keybase.io/{username}",
        joined=_iso(basics.get("ctime")),
        avatar_url=_avatar(profile),
    )

    # External links are the proven identities — the whole point of Keybase.
    proofs = _proof_list(profile)
    proven = [p for p in proofs if p.get("state") in (1, None)]
    unverified = len(proofs) - len(proven)
    links: list[str] = []
    for proof in proven:
        link = _proof_link(proof)
        if link and link not in links:
            links.append(link)
    if links:
        set_fields(result, external_links=links)
        add_note(result, f"{len(links)} proven identity proof(s) on file "
                         "(Keybase-signed, not just claimed)")
    else:
        add_note(result, "no proven identity proofs on file")
    if unverified:
        add_note(result, f"{unverified} pending/revoked proof(s) not counted "
                         "as proven identities")

    crypto = ((profile.get("proofs_summary") or {}).get("cryptocurrency")) or []
    types = sorted({_text(c.get("type")) for c in crypto
                    if isinstance(c, dict) and _text(c.get("type"))})
    if types:
        add_note(result, f"{len(crypto)} cryptocurrency address(es) on file: "
                         + ", ".join(types))

    # Follower/following live behind other Keybase endpoints, not the public
    # lookup — counts and lists both, so this is a wall like every other
    # keyless adapter's.
    add_wall(result, "followers", "followers/following lists",
             "not exposed by the public lookup endpoint")


def collect(page, cfg, handle: str, result: dict) -> None:
    """Resolve the handle and pull profile + proven proofs. Keyless.

    ``page`` is always None here (``browser=False``) — kept in the signature
    so every adapter shares one call shape.
    """
    handle = (handle or "").strip().lstrip("@")
    if not _LOGIN_RE.fullmatch(handle):
        result["error"] = (
            f"'{handle}' is not a valid Keybase username — letters, digits "
            "and underscores only, 2-16 characters, not starting with a "
            "separator"
        )
        return
    handle = handle.lower()
    result["handle"] = handle

    try:
        with httpx.Client(timeout=_TIMEOUT,
                          headers={"Accept": "application/json"}) as client:
            status, data = _get(client, {"usernames": handle, "fields": _FIELDS})
            if status != 200 or not isinstance(data, dict):
                result["error"] = f"keybase.io returned HTTP {status} for @{handle}"
                return
            api_status = data.get("status") or {}
            if api_status.get("code") not in (0, None):
                # Keybase's own rejection (e.g. INPUT_ERROR) — surface its
                # wording rather than inventing one.
                desc = _text(api_status.get("desc")) or _text(api_status.get("name"))
                result["error"] = (f"keybase.io rejected @{handle}: {desc}"
                                   if desc else f"keybase.io rejected @{handle}")
                return
            them = data.get("them") or []
            profile = them[0] if them and isinstance(them[0], dict) else None
            if profile is None:
                result["error"] = f"no Keybase account found for @{handle}"
                return
            returned = _text((profile.get("basics") or {}).get("username"))
            if returned and returned.lower() != handle:
                add_note(result, f"@{handle} resolves to @{returned} on Keybase")
            normalize(profile, result)
            result["source"] = "keybase.io public lookup (keyless)"
    except httpx.TimeoutException:
        result["error"] = "keybase.io timed out — retry later"
    except Exception as exc:
        result["error"] = f"keybase collection failed: {' '.join(str(exc).split())[:140]}"


def _get(client: httpx.Client, params: dict):
    """GET the lookup resource. Returns (status, json-or-None)."""
    try:
        response = client.get(API, params=params)
    except Exception:
        return 0, None
    if response.status_code != 200:
        return response.status_code, None
    try:
        data = response.json()
    except Exception:
        return response.status_code, None
    return response.status_code, data


platform = registry.register(registry.Platform(
    key="keybase",
    label="Keybase",
    homepage="https://keybase.io",
    url="https://keybase.io/{handle}",
    capabilities=CAPABILITIES,
    login="none",
    browser=False,
    collect=collect,
))

"""Mastodon adapter — keyless collection over the public REST API.

No browser, no login, no API key: ``/api/v1/accounts/lookup`` resolves a
handle and ``/api/v1/accounts/:id/statuses`` returns recent posts, all
keyless on any open instance. The harness therefore runs this adapter with
``browser=False`` (``page`` arrives None) and it talks to the instance
directly with httpx, which picks up the operator's proxy from the
environment (``ALL_PROXY``) on its own.

Handles look like ``user`` (resolved on mastodon.social) or the portable
``user@instance`` form. Remote accounts are fetched from their home
instance, derived from the canonical account URL the lookup returns.

``normalize`` is pure and offline-testable, mirroring the Instagram
adapter's split: same fixtures-in, schema-out discipline.
"""

from __future__ import annotations

import html as _html
import ipaddress as _ipaddress
import re as _re

import httpx

from .. import registry
from ..schema import add_note, add_wall, set_fields

CAPABILITIES = (
    "profile", "bio", "followers", "following", "post_count", "posts",
    "avatar", "private", "joined", "links",
)

# Lookup resolvers, tried in order. The first 200 with an account id wins;
# a dead instance costs one timeout, not the scan.
RESOLVERS = ("mastodon.social", "mastodon.online")

_TIMEOUT = 20.0
_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
)

_WS_RE = _re.compile(r"\s+")
_TAG_RE = _re.compile(r"<[^>]+>")
_HREF_RE = _re.compile(r'href\s*=\s*"([^"]+)"')


def _text(value) -> str:
    """Mastodon bios and posts are HTML — strip tags, unescape, flatten."""
    if not value:
        return ""
    return _WS_RE.sub(" ", _html.unescape(_TAG_RE.sub(" ", str(value)))).strip()


def _link_href(value) -> str:
    """The href inside a verified profile-field fragment.

    The link *text* is Mastodon rich-link markup — invisible scheme
    spans around the display host — so tag-stripping the fragment yields
    "https:// github.com/x" (note the space). The href attribute is the
    actual verified URL; parse it instead of stripping. http(s) only:
    a server-returned fragment is third-party content.
    """
    match = _HREF_RE.search(str(value or ""))
    if not match:
        return ""
    href = _html.unescape(match.group(1)).strip()
    return href if href.startswith(("http://", "https://")) else ""


def _host_of(url: str) -> str:
    try:
        return httpx.URL(url or "").host or ""
    except Exception:
        return ""


def _valid_host(host: str) -> bool:
    """Public DNS names only: dotted, no IP literals, sane label lengths.

    Both candidate hosts here are untrusted — the instance half of the
    handle comes straight from operator input, and the home host comes
    from a server-returned account URL. Without this, either could aim
    httpx at loopback, link-local, or intranet addresses (SSRF) on any
    token-holder's behalf. Fediverse instances are public DNS names, so
    a dotted non-IP hostname rejects ~nothing legitimate.
    """
    host = (host or "").strip().lower().rstrip(".")
    if not host or "." not in host or len(host) > 253:
        return False
    if _re.fullmatch(r"[a-z0-9.-]+", host) is None:
        # No ports, paths, userinfo, or whitespace — a bare hostname only.
        return False
    try:
        _ipaddress.ip_address(host)
        return False
    except ValueError:
        pass
    return all(part and len(part) <= 63 for part in host.split("."))


def normalize(account: dict, result: dict) -> None:
    """Map a Mastodon account object onto the normalized schema.

    Pure and offline-testable: no network.
    """
    if not isinstance(account, dict) or not account.get("id"):
        return
    result["found"] = True

    fields = [f for f in (account.get("fields") or []) if isinstance(f, dict)]
    # Verified fields are HTML fragments; the href is the verified URL.
    # (Tag-stripping the fragment mangles Mastodon's rich-link markup
    # into "https:// host" — parse, don't strip.)
    links = [_link_href(f.get("value", "")) for f in fields if f.get("verified_at")]
    links = [link for link in links if link]

    set_fields(
        result,
        display_name=_text(account.get("display_name")) or account.get("username"),
        bio=_text(account.get("note")),
        url=account.get("url") or result.get("url"),
        follower_count=account.get("followers_count"),
        following_count=account.get("following_count"),
        post_count=account.get("statuses_count"),
        private=bool(account.get("locked")),
        joined=account.get("created_at"),
        avatar_url=account.get("avatar"),
        external_links=links,
    )

    if account.get("bot"):
        add_note(result, "automated (bot) account")
    if account.get("discoverable") is False:
        add_note(result, "opted out of discovery — harder to find via search")

    # Lists are paginated endpoints; a cheap keyless pass reports counts
    # only, and says so, rather than implying full follower enumeration.
    add_wall(result, "followers", "followers list", "counts only — list endpoints skipped on a keyless pass")
    add_wall(result, "following", "following list", "counts only — list endpoints skipped on a keyless pass")


def normalize_posts(statuses, result: dict) -> None:
    """Map status objects onto the schema's post list. Pure."""
    posts = []
    for status in statuses or []:
        if not isinstance(status, dict):
            continue
        posts.append({
            "id": status.get("id"),
            "url": status.get("url"),
            "caption": _text(status.get("content")) or "(no text)",
            "media_type": (status.get("media_attachments") or [{}])[0].get("type")
            if status.get("media_attachments") else None,
            "likes": status.get("favourites_count"),
            "comments": status.get("replies_count"),
            "timestamp": status.get("created_at"),
        })
    result["posts"] = posts


def collect(page, cfg, handle: str, result: dict) -> None:
    """Resolve the handle and pull profile + recent posts. Keyless.

    ``page`` is always None here (``browser=False``) — kept in the
    signature so every adapter shares one call shape.
    """
    handle = (handle or "").strip().lstrip("@")
    if "@" in handle:
        user, _, instance = handle.partition("@")
        if instance and not _valid_host(instance):
            result["error"] = f"invalid instance hostname: {instance[:80]}"
            return
        query = f"{user}@{instance}" if instance else user
    else:
        user, instance, query = handle, "", handle

    headers = {"User-Agent": _UA, "Accept": "application/json"}
    try:
        with httpx.Client(timeout=_TIMEOUT, headers=headers) as client:
            account = _lookup(client, query)
            if account is None:
                result["error"] = f"no Mastodon account found for @{handle}"
                return
            if instance and account.get("acct", "").lower() != query.lower():
                # Resolver returned a different account than asked for —
                # report it, don't silently swap identities.
                add_note(result, f"resolver returned @{account.get('acct')} for @{query}")
            normalize(account, result)
            home = _host_of(account.get("url")) or RESOLVERS[0]
            if not _valid_host(home):
                # A hostile or broken instance answered lookup with an
                # account URL pointing somewhere httpx must not go —
                # keep the profile, skip its posts, say why.
                add_note(result, "recent posts skipped (home instance hostname invalid)")
                return
            result["source"] = f"mastodon API ({home})"
            statuses = _statuses(client, home, str(account["id"]))
            if statuses is not None:
                normalize_posts(statuses, result)
            else:
                add_note(result, "recent posts unavailable (statuses endpoint failed)")
    except httpx.TimeoutException:
        result["error"] = "mastodon instance timed out — retry later"
    except Exception as exc:
        result["error"] = f"mastodon collection failed: {' '.join(str(exc).split())[:140]}"


def _lookup(client: httpx.Client, query: str) -> dict | None:
    for resolver in RESOLVERS:
        try:
            response = client.get(
                f"https://{resolver}/api/v1/accounts/lookup",
                params={"acct": query},
            )
        except Exception:  # noqa: S112 - dead resolver costs a retry, not the scan
            continue
        if response.status_code == 200:
            try:
                account = response.json()
            except Exception:  # noqa: S112 - bad JSON from one resolver, try the next
                continue
            if isinstance(account, dict) and account.get("id"):
                return account
        elif response.status_code not in (401, 403, 404, 422):
            continue
    return None


def _statuses(client: httpx.Client, host: str, account_id: str):
    try:
        response = client.get(
            f"https://{host}/api/v1/accounts/{account_id}/statuses",
            params={"limit": 12, "exclude_reblogs": "true"},
        )
    except Exception:
        return None
    if response.status_code != 200:
        return None
    try:
        data = response.json()
    except Exception:
        return None
    return data if isinstance(data, list) else None


platform = registry.register(registry.Platform(
    key="mastodon",
    label="Mastodon",
    homepage="https://joinmastodon.org",
    url="https://mastodon.social/@{handle}/",
    capabilities=CAPABILITIES,
    login="none",
    browser=False,
    collect=collect,
))

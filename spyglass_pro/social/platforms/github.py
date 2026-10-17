"""GitHub adapter — keyless collection over the public REST API.

``api.github.com`` serves full profiles with no token: name, bio, blog,
location, a contact email when the user published one, follower/following
counts, public repository counts and the account creation date. The
keyless budget is 60 requests/hour per IP, which is valuable but small,
so the adapter spends at most two: the profile and the ten most recently
updated public repositories (mapped onto the schema's ``posts`` list —
for a GitHub account that *is* the recent activity). Follower/following
lists exist but are skipped and reported as walls, same policy as the
other keyless adapters.

Logins are validated locally before any request: GitHub logins are
alphanumerics with single interior hyphens, at most 39 characters. A
malformed target fails without spending budget rather than generating a
404 that looks like a real "no such user" answer.

Renamed accounts are followed (301 → final profile) and the rename is
noted rather than silently swapped, mirroring Mastodon's resolver note.
"""

from __future__ import annotations

import re as _re

import httpx

from .. import registry
from ..schema import add_note, add_wall, set_fields

CAPABILITIES = (
    "profile", "bio", "followers", "following", "post_count", "posts",
    "avatar", "joined", "location", "website", "links", "contact",
)

API = "https://api.github.com"

_TIMEOUT = 20.0
# Sixty anonymous requests an hour per IP — small enough that every
# request is accounted for in notes on the result.
_KEYLESS_LIMIT = 60
_RECENT_REPOS = 10

# GitHub usernames: [a-zA-Z0-9], single interior hyphens, 1-39 chars,
# may not start or end with a hyphen. Enforced locally so a typo'd
# target fails cheaply instead of burning budget on a guaranteed 404.
_LOGIN_RE = _re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38}$")

_WS_RE = _re.compile(r"\s+")


def _text(value) -> str:
    return _WS_RE.sub(" ", str(value or "")).strip()


def _website(value) -> str | None:
    """GitHub lets the profile blog be a bare domain — the renderer's
    link fields are scheme-allowlisted, so give it one when it has none."""
    value = _text(value)
    if not value:
        return None
    if not _re.match(r"^https?://", value, _re.I):
        value = "https://" + value.lstrip("/")
    return value


def normalize(profile: dict, result: dict) -> None:
    """Map a REST user object onto the normalized schema. Pure, offline."""
    if not isinstance(profile, dict) or not profile.get("login"):
        return
    result["found"] = True
    login = profile.get("login")
    links = [_website(profile.get("blog")) or None]
    if profile.get("twitter_username"):
        links.append(f"https://x.com/{profile['twitter_username']}")
    set_fields(
        result,
        display_name=_text(profile.get("name")) or login,
        bio=_text(profile.get("bio")),
        url=profile.get("html_url") or f"https://github.com/{login}",
        follower_count=profile.get("followers"),
        following_count=profile.get("following"),
        # GitHub has no posts; public repositories are the count the
        # keyless profile actually exposes.
        post_count=profile.get("public_repos"),
        joined=profile.get("created_at"),
        location=_text(profile.get("location")),
        website=_website(profile.get("blog")),
        contact_email=profile.get("email"),
        avatar_url=profile.get("avatar_url"),
        external_links=[link for link in links if link],
    )
    if (profile.get("type") or "").lower() == "organization":
        add_note(result, "organization account, not a personal profile")
    if profile.get("hired"):
        add_note(result, "profile is marked 'available for hire'")
    # Follower/follow users exist but are list endpoints; counts only, and
    # the lists are walls like every other keyless adapter's.
    add_wall(result, "followers", "followers list",
             "counts only — list endpoints skipped on a keyless pass")
    add_wall(result, "following", "following list",
             "counts only — list endpoints skipped on a keyless pass")


def normalize_repos(repos, result: dict) -> None:
    """Map recent public repos onto the schema's post list. Pure, offline."""
    posts = []
    for repo in repos or []:
        if not isinstance(repo, dict):
            continue
        name = repo.get("name") or repo.get("full_name")
        posts.append({
            "id": repo.get("id"),
            "url": repo.get("html_url") or name,
            "caption": _text(repo.get("description")) or name,
            "media_type": None,
            "likes": repo.get("stargazers_count"),
            "comments": repo.get("forks_count"),
            "timestamp": repo.get("pushed_at") or repo.get("updated_at")
                         or repo.get("created_at"),
        })
    result["posts"] = posts


def _remaining(headers: dict) -> int | None:
    try:
        return int(headers.get("x-ratelimit-remaining", ""))
    except (TypeError, ValueError):
        return None


def _budget_note(headers: dict, result: dict) -> None:
    """Say plainly what the collection cost and what is left.

    Sixty keyless requests an hour per IP is a real operational limit —
    an operator mixing email sweeps and GitHub lookups can exhaust it
    without noticing unless the number is on the result.
    """
    remaining = _remaining(headers)
    if remaining is None:
        return
    add_note(result, f"keyless GitHub budget: {remaining}/{_KEYLESS_LIMIT} "
                     "requests left this hour from this IP")


def collect(page, cfg, handle: str, result: dict) -> None:
    """Profile + recent public repos. Keyless, ``page`` is always None."""
    handle = (handle or "").strip().lstrip("@")
    if not _LOGIN_RE.fullmatch(handle):
        result["error"] = (
            f"'{handle}' is not a valid GitHub login — alphanumerics and "
            "single interior hyphens only, 1-39 characters"
        )
        return
    result["handle"] = handle

    headers = {"Accept": "application/vnd.github+json"}
    try:
        with httpx.Client(timeout=_TIMEOUT, headers=headers,
                          follow_redirects=True) as client:
            status, profile, rh = _get(client, f"/users/{handle}")
            if status == 404:
                result["error"] = f"no GitHub account found for @{handle}"
                return
            if status in (403, 429) and _remaining(rh) == 0:
                result["error"] = (
                    "keyless GitHub budget exhausted (60 requests/hour per "
                    "IP) — set a GITHUB_TOKEN in the settings vault to use "
                    "the authenticated 5,000/hour budget, or retry later"
                )
                return
            if status in (403, 429):
                # Budget was NOT the cause (headers show requests left), so
                # this is GitHub's secondary rate limit or abuse detection —
                # common right after a burst of keyless scans.
                result["error"] = (
                    f"github.com rejected @{handle} beyond the primary budget "
                    "(secondary rate limit / abuse detection) — wait a few "
                    "minutes before retrying, or route the server through "
                    "SPYGLASS_PROXY to a different IP")
                return
            if status != 200 or not isinstance(profile, dict):
                result["error"] = (f"github.com returned HTTP {status} for "
                                   f"@{handle}")
                return
            login = (profile.get("login") or "").lower()
            if login and login != handle.lower():
                # A rename; report it rather than silently swapping
                # identities (same policy as Mastodon's resolver note).
                add_note(result, f"@{handle} is now @{profile.get('login')} "
                                 "(account renamed)")
            _budget_note(rh, result)
            normalize(profile, result)
            result["source"] = "api.github.com (keyless)"
            if result.get("post_count"):
                add_note(result, "post count = public repository count")
            status2, repos, _rh2 = _get(
                client, f"/users/{handle}/repos",
                {"sort": "updated", "direction": "desc", "per_page": _RECENT_REPOS})
            if status2 == 200 and isinstance(repos, list):
                normalize_repos(repos, result)
                shown = len(result["posts"])
                add_note(result, f"posts = {shown} most recently updated "
                                 "public repositories")
            else:
                add_note(result, "recent repositories unavailable "
                                 "(repos endpoint failed)")
    except httpx.TimeoutException:
        result["error"] = "api.github.com timed out — retry later"
    except Exception as exc:
        result["error"] = f"github collection failed: {' '.join(str(exc).split())[:140]}"


def _get(client: httpx.Client, path: str, params: dict | None = None):
    """GET one API resource. Returns (status, json-or-None, lowercase-headers)."""
    try:
        response = client.get(f"{API}{path}", params=params)
    except Exception:
        return 0, None, {}
    lower = {k.lower(): v for k, v in response.headers.items()}
    if response.status_code != 200:
        return response.status_code, None, lower
    try:
        data = response.json()
    except Exception:
        return response.status_code, None, lower
    return response.status_code, data, lower


platform = registry.register(registry.Platform(
    key="github",
    label="GitHub",
    homepage="https://github.com",
    url="https://github.com/{handle}",
    capabilities=CAPABILITIES,
    login="none",
    browser=False,
    collect=collect,
))

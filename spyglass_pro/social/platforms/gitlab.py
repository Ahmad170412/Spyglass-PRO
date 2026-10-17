"""GitLab adapter — keyless collection over the public REST API.

``gitlab.com`` serves profiles with no token, but be honest about the
shape: unauthenticated user objects are the **short** form — name,
username, avatar, profile URL, account state, and a contact email only
when the user published one. Bio, location, website and the account
creation date are admin-only fields; GitLab simply never returns them
here, so they are not promised in capabilities and never fabricated.
Public projects carry the substance: names, descriptions, star/fork
counts and last-activity times, with GitLab's own ``X-Total`` header
giving the *real* public-project count for the account.

The keyless budget is generous (500 requests/minute per IP,
``throttle_unauthenticated_api``) and the adapter spends at most two: the
user lookup and the ten most recently active public projects — which,
for a GitLab account, are the recent activity. The optional
``GITLAB_TOKEN`` environment variable is honoured when present and the
budget note then reads GitLab's own headers instead of assuming 500,
because the only version of that sentence that stays true is the one
the instance itself reports.

Unknown handles: ``GET /users?username=X`` answers with an empty list
(not a 404), so "no such user" is derived from an empty result — which
also makes this the one adapter whose miss case is cheap and exact;
a locally-validated malformed handle never becomes a plausible miss.

GitLab usernames allow alphanumerics plus ``_ `` ``-`` and ``.``, may
not start with a separator, and can run long — validated locally so a
typo'd target fails without spending budget, same policy as GitHub.
"""

from __future__ import annotations

import os
import re as _re

import httpx

from .. import registry
from ..schema import add_note, set_fields

CAPABILITIES = (
    "profile", "avatar", "contact", "post_count", "posts",
)

API = "https://gitlab.com/api/v4"

_TIMEOUT = 20.0
# 500/minute per IP unauthenticated (throttle_unauthenticated_api) —
# generous, but the number is still read from GitLab's own headers and
# reported on every result, because sweeps can chew through it too.
_RECENT_PROJECTS = 10
_KEYLESS_LIMIT = 500

# GitLab usernames (namespace paths): alphanumerics plus _ - . — must not
# start with a separator. A cheap prefilter; the API always has the truth.
_LOGIN_RE = _re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,254}$")

_WS_RE = _re.compile(r"\s+")


def _text(value) -> str:
    return _WS_RE.sub(" ", str(value or "")).strip()


def normalize(profile: dict, result: dict) -> None:
    """Map the short unauthenticated user object onto the schema. Pure."""
    if not isinstance(profile, dict) or not profile.get("username"):
        return
    result["found"] = True
    login = profile["username"]
    set_fields(
        result,
        display_name=_text(profile.get("name")) or login,
        url=profile.get("web_url") or f"https://gitlab.com/{login}",
        contact_email=profile.get("public_email") or None,
        avatar_url=profile.get("avatar_url"),
        # post_count is filled from GitLab's X-Total on the projects leg;
        # nothing is guessed here when that header is absent.
    )
    state = (profile.get("state") or "").lower()
    if state and state != "active":
        add_note(result, f"account state is '{state}' "
                         "— it may not match its public activity")
    if profile.get("locked"):
        add_note(result, "account is locked by the instance")


def normalize_projects(projects, result: dict) -> None:
    """Map recently active public projects onto the post list. Pure, offline."""
    posts = []
    for project in projects or []:
        if not isinstance(project, dict):
            continue
        name = project.get("name") or project.get("path")
        posts.append({
            "id": project.get("id"),
            "url": project.get("web_url") or name,
            "caption": _text(project.get("description")) or name,
            "media_type": None,
            "likes": project.get("star_count"),
            "comments": project.get("forks_count"),
            "timestamp": project.get("last_activity_at")
                         or project.get("updated_at")
                         or project.get("created_at"),
        })
    result["posts"] = posts


def _limit_remaining(headers: dict) -> tuple[int | None, int | None]:
    def _int(key):
        try:
            return int(headers.get(key, ""))
        except (TypeError, ValueError):
            return None
    return _int("ratelimit-limit"), _int("ratelimit-remaining")


def _budget_note(headers: dict, result: dict, authenticated: bool = False) -> None:
    """Report the numbers — never assume 500, never guess the tier.

    The scope wording follows what the adapter actually *sent* (the
    GITLAB_TOKEN environment variable), because GitLab occasionally serves
    a request with a smaller per-endpoint limit bucket than 500 — the one
    version of this sentence that stays true is: numbers from the
    response, tier from the request.
    """
    limit, remaining = _limit_remaining(headers)
    if remaining is None:
        return
    scope = ("GitLab budget (GITLAB_TOKEN authenticated)"
             if authenticated else "keyless GitLab budget")
    add_note(result, f"{scope}: {remaining}/{limit or _KEYLESS_LIMIT} "
                     "requests left this minute from this IP")


def collect(page, cfg, handle: str, result: dict) -> None:
    """Profile + recently active public projects. Keyless by default."""
    handle = (handle or "").strip().lstrip("@")
    if not _LOGIN_RE.fullmatch(handle):
        result["error"] = (
            f"'{handle}' is not a valid GitLab handle — alphanumerics plus "
            "_ - . only, and it cannot start with a separator"
        )
        return
    result["handle"] = handle

    token = os.environ.get("GITLAB_TOKEN", "").strip()
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        with httpx.Client(timeout=_TIMEOUT, headers=headers) as client:
            status, users, rh = _get(
                client, "/users", {"username": handle})
            if status in (403, 429) and _limit_remaining(rh)[1] == 0:
                result["error"] = (
                    "keyless GitLab budget exhausted (500 requests/minute "
                    "per IP, unauthenticated) — it resets within the "
                    "minute; systematic sweeps should pace themselves or "
                    "route through SPYGLASS_PROXY")
                return
            if status in (403, 429):
                # Budget was NOT the cause — this is GitLab's IP-level
                # abuse gating on a throttled address that still had
                # requests left in its window.
                result["error"] = (
                    f"gitlab.com rejected @{handle} beyond the request "
                    "budget (secondary rate limit / abuse detection) — "
                    "wait a few minutes before retrying, or route the "
                    "server through SPYGLASS_PROXY to a different IP")
                return
            if status != 200 or not isinstance(users, list):
                result["error"] = (f"gitlab.com returned HTTP {status} for "
                                   f"@{handle}")
                return
            if not users or not isinstance(users[0], dict):
                result["error"] = f"no GitLab account found for @{handle}"
                return
            profile = users[0]
            username = (profile.get("username") or "").lower()
            if username and username != handle.lower():
                add_note(result, f"@{handle} resolves to @{profile.get('username')} "
                                 "(different casing on the instance)")
            _budget_note(rh, result, authenticated=bool(token))
            normalize(profile, result)
            result["source"] = "gitlab.com/api/v4 (keyless)"
            user_id = profile.get("id")
            if user_id is None:
                add_note(result, "public projects unavailable "
                                 "(API returned no user id)")
                return
            status2, projects, rh2 = _get(
                client, f"/users/{user_id}/projects",
                {"order_by": "last_activity_at", "sort": "desc",
                 "per_page": _RECENT_PROJECTS})
            if status2 != 200 or not isinstance(projects, list):
                add_note(result, "recent projects unavailable "
                                 "(projects endpoint failed)")
                return
            total = _total_count(rh2)
            if total:
                result["post_count"] = total
                add_note(result, "post count = public project count "
                                 "(GitLab X-Total)")
            normalize_projects(projects, result)
            shown = len(result["posts"])
            note = (f"posts = {shown} most recently active public projects")
            if total and shown < total:
                note += f" (of {total} public projects)"
            add_note(result, note)
    except httpx.TimeoutException:
        result["error"] = "gitlab.com timed out — retry later"
    except Exception as exc:
        result["error"] = (f"gitlab collection failed: "
                           f"{' '.join(str(exc).split())[:140]}")


def _total_count(headers: dict) -> int | None:
    """GitLab exposes the relation's total as X-Total on projects pages."""
    try:
        total = int(headers.get("x-total", ""))
    except (TypeError, ValueError):
        return None
    return total if total > 0 else None


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
    key="gitlab",
    label="GitLab",
    homepage="https://gitlab.com",
    url="https://gitlab.com/{handle}",
    capabilities=CAPABILITIES,
    login="none",
    browser=False,
    collect=collect,
))

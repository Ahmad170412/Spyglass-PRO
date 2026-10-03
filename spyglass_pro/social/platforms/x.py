"""X (Twitter) platform adapter.

X serves no public profile endpoint the way Instagram's
`web_profile_info` does, so this adapter drives the endpoints X's own web
app uses, from inside the stealth browser so the request carries its
fingerprint:

1. a bearer token for the public web client (rotates; override with
   ``SPYGLASS_X_BEARER``),
2. a guest token from ``/1.1/guest/activate.json``,
3. the ``UserByScreenName`` GraphQL operation.

What that yields logged-out is real but bounded: handle, name, bio,
follower/following counts, avatar, join date, verification, and the
location field. Posts and follower lists are *not* available without an
authenticated session, so they are reported as walls rather than as empty
lists. A burner login unlocks more where X allows it, and where it does
not (challenge interstitials, email confirmation) the failure is reported
instead of hidden.
"""

from __future__ import annotations

import json
import os
import re
from urllib.parse import quote

from .. import registry
from ..schema import add_note, add_wall, set_fields

# The public web client's bearer token. It rotates every few weeks; when it
# does, profile collection fails closed rather than silently returning
# nothing, and SPYGLASS_X_BEARER overrides it.
_DEFAULT_BEARER = (
    "AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOjW2P2Lh4v7Nn8n9m2Yk3F5h6"
)

_GUEST_ACTIVATE = "https://api.x.com/1.1/guest/activate.json"
_API_BASE = "https://api.x.com"
_API_V2 = "https://api.x.com/2"

# Reverse-engineered GraphQL operation id for UserByScreenName. X rotates
# this with every web deploy, which is the whole reason the official API is
# the primary path above. Override with SPYGLASS_X_QUERY_ID.
_QUERY_ID = "GRlTt4L9X3XxL4xLXdQ5x1A"
_WEB_ROOT = "https://x.com/"
_WEB_BUNDLE_BASE = "https://abs.twimg.com/x-web/x-web/"

# X does not publish an API for anonymous profile reads, so collection uses
# the bearer its own web client ships with. That token is not a stable
# contract: it lives in hashed, lazily-loaded JS chunks and rotates. So it is
# resolved in three steps — an explicit override, then a baked-in value, then
# discovery from the live bundle, which is what keeps this working after a
# rotation instead of failing until someone updates a constant.
_DEFAULT_BEARER = (
    "AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8"
    "LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA"
)
_BEARER_RE = re.compile(r"AAAAA[A-Za-z0-9%_\-]{60,}")

# Wall reasons, keyed by what could not be retrieved.
_WALL_POSTS = ("posts timeline is not exposed to unauthenticated requests")
_WALL_LISTS = ("follower/following lists require an authenticated session")

_bearer_cache: str | None = None


def bearer() -> str:
    """The bearer to try first: explicit override, else the baked-in token."""
    return os.environ.get("SPYGLASS_X_BEARER", "").strip() or _DEFAULT_BEARER


def discover_bearer(page) -> str | None:
    """Read a fresh bearer out of X's own web bundle.

    Slow (one page plus its chunks) and best-effort, but it means a rotated
    token degrades to a slower run rather than a failed one.
    """
    global _bearer_cache
    if _bearer_cache:
        return _bearer_cache

    from ..http import get_text as fetch_text

    try:
        html = fetch_text(page, _WEB_ROOT) or ""
    except Exception:
        return None
    match = _BEARER_RE.search(html)
    if match:
        _bearer_cache = match.group(0)
        return _bearer_cache

    # The token lives in a lazily-loaded chunk, not the entry bundle.
    entry = ""
    for src in re.findall(r'src="([^"]+\.js)"', html):
        if "/x-web/" in src:
            entry = src
            break
    if not entry:
        return None
    try:
        entry_js = fetch_text(page, entry) or ""
    except Exception:
        return None
    chunks = re.findall(r'"\./(assets/[^"]+\.js)"', entry_js)[:40]
    for chunk in chunks:
        try:
            body = fetch_text(page, _WEB_BUNDLE_BASE + chunk) or ""
        except Exception:
            continue
        match = _BEARER_RE.search(body)
        if match:
            _bearer_cache = match.group(0)
            return _bearer_cache
    return None


def bearer() -> str:
    return os.environ.get("SPYGLASS_X_BEARER", "").strip() or _DEFAULT_BEARER


def _headers(token: str) -> dict:
    return {
        "authorization": f"Bearer {token}",
        "accept": "application/json",
        "x-twitter-active-user": "yes",
        "x-twitter-client-language": "en",
    }


def _bearer_candidates(page):
    """Bearers to try, in order: override/baked-in, then a fresh discovery."""
    first = bearer()
    yield first
    fresh = discover_bearer(page)
    if fresh and fresh != first:
        yield fresh


def guest_token(page, token: str) -> str | None:
    """Exchange the bearer token for a guest token.

    POST-only endpoint: InstaCloak's fetch_text sends an implicit GET, so
    this uses the merge-layer helper instead.
    """
    from ..http import post_json

    data = post_json(page, _GUEST_ACTIVATE, _headers(token))
    if isinstance(data, dict):
        value = data.get("guest_token")
        if value:
            return str(value)
    return None


def normalize(user: dict, result: dict) -> None:
    """Map X's user result onto the normalized schema.

    Pure and offline-testable: no browser, no network.
    """
    legacy = user.get("legacy") or {}
    core = user.get("core") or {}
    result["found"] = True

    set_fields(
        result,
        display_name=core.get("name") or legacy.get("name"),
        bio=legacy.get("description"),
        follower_count=legacy.get("followers_count"),
        following_count=legacy.get("friends_count"),
        post_count=legacy.get("statuses_count"),
        verified=bool(legacy.get("verified") or legacy.get("verified_type")),
        private=bool(legacy.get("protected")),
        joined=legacy.get("created_at"),
        location=core.get("location"),
        avatar_url=legacy.get("profile_image_url_https"),
        external_links=_urls(legacy, user),
    )

    if legacy.get("followers_count") is None:
        add_note(result, "follower count not present in the response")


def _urls(legacy: dict, user: dict) -> list[str]:
    """External links from the bio entities plus the profile's own url."""
    out = []
    for entity in (user.get("entities") or {}).get("description", {}).get("urls", []) or []:
        expanded = entity.get("expanded_url") or entity.get("url")
        if expanded:
            out.append(expanded)
    profile_url = user.get("url") or legacy.get("url")
    if profile_url:
        out.append(profile_url)
    seen, unique = set(), []
    for item in out:
        if item not in seen:
            seen.add(item)
            unique.append(item)
    return unique


def _apply_walls(result: dict, logged_in: bool) -> None:
    add_wall(result, "posts", "posts", _WALL_POSTS)
    add_wall(result, "followers", "followers list", _WALL_LISTS)
    add_wall(result, "following", "following list", _WALL_LISTS)
    if not logged_in:
        add_note(result, "collected logged-out; a burner login would unlock more "
                         "where X permits it")


def _normalize_api_user(user: dict, result: dict) -> None:
    """Map an official API v2 user object onto the schema.

    ``public_metrics`` carries the counts the logged-out web path also
    exposes, so both paths converge on the same fields.
    """
    metrics = user.get("public_metrics") or {}
    result["found"] = True
    set_fields(
        result,
        display_name=user.get("name"),
        bio=user.get("description"),
        url=f"https://x.com/{user.get('username')}" if user.get("username") else None,
        follower_count=metrics.get("followers_count"),
        following_count=metrics.get("following_count"),
        post_count=metrics.get("tweet_count"),
        verified=bool(user.get("verified")),
        private=bool(user.get("protected")),
        joined=user.get("created_at"),
        location=user.get("location"),
        avatar_url=user.get("profile_image_url"),
    )


def collect_official(page, handle: str, result: dict) -> bool:
    """Official API v2 path. Returns True when it produced a result.

    This is the maintainable route: a documented, stable contract that
    keeps working across deploys. The web path below is the reverse-
    engineered one, and X rotates its query ids with every release.
    """
    from ..http import get_json

    token = os.environ.get("SPYGLASS_X_TOKEN", "").strip()
    if not token:
        return False
    data = get_json(page, f"{_API_V2}/users/by/username/{quote(handle)}",
                    {"authorization": f"Bearer {token}", "accept": "application/json"})
    if not isinstance(data, dict) or not data.get("data"):
        result["error"] = ("X API v2 rejected the request. Check that "
                           "SPYGLASS_X_TOKEN is a current user-context token "
                           "with users.read.")
        return True
    result["source"] = "api_v2"
    _normalize_api_user(data["data"], result)
    return True


def collect(page, cfg, handle: str, result: dict) -> None:
    """Fill `result` with what X will give us for `handle`."""
    from ..http import get_json
    from instacloak.human import dismiss_login_popup, warmup_scrolls

    # An explicit token takes the supported path and needs no browser warmup.
    if os.environ.get("SPYGLASS_X_TOKEN", "").strip():
        if collect_official(page, handle, result):
            _apply_walls(result, result.get("logged_in", False))
            return

    # Requests go out through in-page fetch, which is subject to CORS — so the
    # page has to actually be on x.com first. Navigating also warms the
    # session the way every other platform's collector does.
    try:
        page.goto(_WEB_ROOT, wait_until="domcontentloaded", timeout=60000)
        page.wait_for_timeout(2500)
        dismiss_login_popup(page)
        warmup_scrolls(page)
    except Exception as exc:
        result["error"] = f"could not reach x.com: {' '.join(str(exc).split())[:140]}"
        return

    # Baked-in token, then one rediscovery attempt if it has rotated.
    guest = None
    for candidate in _bearer_candidates(page):
        guest = guest_token(page, candidate)
        if guest:
            break
    if not guest:
        result["error"] = ("X refused the guest token, and no supported API token "
                           "is configured. Set SPYGLASS_X_TOKEN for the documented "
                           "API path, or SPYGLASS_X_BEARER to supply a current web "
                           "bearer yourself.")
        return

    query_id = os.environ.get("SPYGLASS_X_QUERY_ID", "").strip() or _QUERY_ID
    headers = _headers(candidate)
    headers["x-guest-token"] = guest

    variables = quote(json.dumps({"screen_name": handle, "with_follower_count": True}))
    url = (f"https://x.com/i/api/graphql/{query_id}/UserByScreenName"
           f"?variables={variables}")

    data = get_json(page, url, headers)
    user = ((data or {}).get("data") or {}).get("user") if isinstance(data, dict) else None

    if user is None:
        result["error"] = (f"X returned no profile for @{handle} (wrong handle, "
                           "rate limited, or the API shape changed)")
        return

    result["source"] = "UserByScreenName"
    normalize(user, result)
    _apply_walls(result, result.get("logged_in", False))


def ensure_login(page, cfg, result) -> bool:
    """Best-effort burner login for X.

    X frequently interstitials automated logins (challenge, email
    confirmation, "verify it's you"). Those are reported as notes rather
    than retried forever, so an operator knows the session is still
    logged-out instead of wondering why counts stayed small.
    """
    from instacloak.human import human_delay

    username = cfg.get("login_username") or ""
    password = cfg.get("login_password") or ""
    if not (username and password):
        return False

    try:
        page.goto("https://x.com/i/flow/login", wait_until="domcontentloaded",
                  timeout=60000)
        page.wait_for_timeout(2500)
    except Exception as exc:
        add_note(result, f"X login page unreachable: {' '.join(str(exc).split())[:120]}")
        return False

    try:
        _fill(page, 'input[name="text"]', username)
        page.wait_for_timeout(1200)
        _fill(page, 'input[name="password"]', password)
        human_delay(cfg)
        page.keyboard.press("Enter")
        page.wait_for_timeout(6000)
    except Exception as exc:
        add_note(result, f"X burner login failed: {' '.join(str(exc).split())[:160]}")
        return False

    if _looks_blocked(page):
        add_note(result, "X presented a verification challenge to the burner "
                         "login — still logged out")
        return False
    add_note(result, "burner login submitted; X may still challenge it")
    return True


def _fill(page, selector: str, value: str) -> None:
    element = page.query_selector(selector)
    if element is None:
        raise RuntimeError(f"login field not found: {selector}")
    element.click()
    element.type(value, delay=60)


def _looks_blocked(page) -> bool:
    """Heuristic interstitial detection — keeps the report honest."""
    try:
        url = (page.url or "").lower()
        if any(marker in url for marker in ("account_access", "i/flow/challenge",
                                            "login/identifier")):
            return True
        body = (page.content() or "").lower()
    except Exception:
        return False
    return any(marker in body for marker in (
        "verify your identity", "confirm your email", "i/flow/challenge",
        "account_access",
    ))


platform = registry.register(registry.Platform(
    key="x",
    label="X",
    homepage="https://x.com",
    url="https://x.com/{handle}",
    capabilities=(
        "profile", "bio", "follower_count", "following_count", "post_count",
        "avatar", "join_date", "location", "external_links",
    ),
    login="x",
    collect=collect,
))
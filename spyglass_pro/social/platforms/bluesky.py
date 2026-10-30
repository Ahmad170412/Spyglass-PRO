"""Bluesky adapter — keyless collection over the public AppView API.

``public.api.bsky.app`` serves profiles, post feeds and counts with no
auth, so like Mastodon this adapter runs with ``browser=False`` and talks
straight to the API with httpx (proxy picked up from ``ALL_PROXY``).

Handles are domains (``user.bsky.social``). A bare word is resolved as
``word.bsky.social`` and the assumption is noted on the result rather
than hidden — a wrong guess must be visible, not silent.

``normalize`` is pure and offline-testable, mirroring the other adapters.
"""

from __future__ import annotations

import re as _re

import httpx

from .. import registry
from ..lists import RECORD_CAP, record
from ..schema import add_note, add_wall, set_fields

CAPABILITIES = (
    "profile", "bio", "followers", "following", "post_count", "posts",
    "avatar", "joined",
)

APPVIEW = "https://public.api.bsky.app/xrpc"

_TIMEOUT = 20.0
_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
)

_WS_RE = _re.compile(r"\s+")


def _text(value) -> str:
    return _WS_RE.sub(" ", str(value or "")).strip()


def _post_url(handle: str, uri: str) -> str:
    """AT-URI (at://did/.../app.bsky.feed.post/<rkey>) → public bsky.app URL."""
    rkey = (uri or "").rstrip("/").rsplit("/", 1)[-1]
    if not rkey or not handle:
        return ""
    return f"https://bsky.app/profile/{handle}/post/{rkey}"


def normalize(profile: dict, result: dict) -> None:
    """Map an AppView profile view onto the normalized schema.

    Pure and offline-testable: no network.
    """
    if not isinstance(profile, dict) or not profile.get("did"):
        return
    result["found"] = True
    handle = profile.get("handle") or result.get("handle")

    set_fields(
        result,
        display_name=_text(profile.get("displayName")) or handle,
        bio=_text(profile.get("description")),
        url=f"https://bsky.app/profile/{handle}" if handle else result.get("url"),
        follower_count=profile.get("followersCount"),
        following_count=profile.get("followsCount"),
        post_count=profile.get("postsCount"),
        joined=profile.get("indexedAt") or profile.get("createdAt"),
        avatar_url=profile.get("avatar"),
    )

    labels = [val for label in (profile.get("labels") or [])
              if isinstance(label, dict) and (val := label.get("val"))]
    if labels:
        add_note(result, "moderation labels: " + ", ".join(labels))
    if profile.get("associated", {}).get("labeler"):
        add_note(result, "account operates a labeler service")

    # Follower/follow lists are paginated endpoints; a cheap keyless pass
    # reports counts only and says so.
    add_wall(result, "followers", "followers list", "counts only — list endpoints skipped on a keyless pass")
    add_wall(result, "following", "following list", "counts only — list endpoints skipped on a keyless pass")


def normalize_feed(feed, handle: str, result: dict) -> None:
    """Map an author-feed page onto the schema's post list. Pure."""
    posts = []
    for item in feed or []:
        if not isinstance(item, dict):
            continue
        post = item.get("post") or {}
        record = post.get("record") or {}
        uri = post.get("uri") or ""
        posts.append({
            "id": uri.rsplit("/", 1)[-1] or None,
            "url": _post_url(handle, uri) or None,
            "caption": _text(record.get("text")) or "(no text)",
            "media_type": None,
            "likes": post.get("likeCount"),
            "comments": post.get("replyCount"),
            "timestamp": record.get("createdAt") or post.get("indexedAt"),
        })
    result["posts"] = posts


def collect(page, cfg, handle: str, result: dict) -> None:
    """Resolve the handle and pull profile + recent posts. Keyless.

    ``page`` is always None here (``browser=False``) — kept in the
    signature so every adapter shares one call shape.
    """
    handle = (handle or "").strip().lstrip("@").lower()
    if not handle:
        return
    if "." not in handle:
        handle = f"{handle}.bsky.social"
        add_note(result, f"bare name resolved as {handle}")
    result["handle"] = handle

    headers = {"User-Agent": _UA, "Accept": "application/json"}
    try:
        with httpx.Client(timeout=_TIMEOUT, headers=headers) as client:
            profile = _get(client, "app.bsky.actor.getProfile", {"actor": handle})
            if profile is None:
                result["error"] = f"no Bluesky account found for @{handle}"
                return
            if profile.get("handle", "").lower() != handle:
                add_note(result, f"AppView returned @{profile.get('handle')} for @{handle}")
            normalize(profile, result)
            result["source"] = "bluesky public AppView"
            feed = _get(client, "app.bsky.feed.getAuthorFeed", {
                "actor": handle, "limit": "40", "filter": "posts_no_replies",
            })
            if feed is not None:
                normalize_feed(feed.get("feed"), profile.get("handle") or handle, result)
            else:
                add_note(result, "recent posts unavailable (feed endpoint failed)")
            # Graph lists: cursor pagination on the public AppView, up to
            # RECORD_CAP; failures wall the gap (social/lists.py owns the
            # completeness verdict).
            did = profile.get("did") or ""
            if did:
                _walk_list(client, did, "followers", "app.bsky.graph.getFollowers",
                           "followers", result.get("follower_count"), result)
                _walk_list(client, did, "following", "app.bsky.graph.getFollows",
                           "follows", result.get("following_count"), result)
    except httpx.TimeoutException:
        result["error"] = "bluesky AppView timed out — retry later"
    except Exception as exc:
        result["error"] = f"bluesky collection failed: {' '.join(str(exc).split())[:140]}"


def _get(client: httpx.Client, method: str, params: dict) -> dict | None:
    try:
        response = client.get(f"{APPVIEW}/{method}", params=params)
    except Exception:
        return None
    if response.status_code != 200:
        return None
    try:
        data = response.json()
    except Exception:
        return None
    return data if isinstance(data, dict) else None


def _walk_list(client: httpx.Client, did: str, kind: str, method: str,
               response_key: str, expected, result: dict) -> None:
    """Follow an AppView cursor up to RECORD_CAP records, walling failures.

    Pages arrive at ~90 records regardless of the requested limit, so a
    short page says nothing about completeness — only a missing cursor
    does. Hitting RECORD_CAP first leaves the block a window (complete
    false), which is what the diff engine keys its refusals on.
    """
    handles: list[str] = []
    cursor: str | None = None
    exhausted = False
    error = None
    pages = 0
    while pages < 60 and len(handles) < RECORD_CAP:
        params = {"actor": did, "limit": "100"}
        if cursor:
            params["cursor"] = cursor
        data = _get(client, method, params)
        if data is None:
            error = "list walk interrupted (AppView error or timeout mid-walk)"
            break
        batch = data.get(response_key)
        if not isinstance(batch, list):
            error = "unexpected AppView list response"
            break
        if not batch:
            exhausted = True
            break
        for entry in batch:
            if isinstance(entry, dict) and entry.get("handle"):
                handles.append(str(entry["handle"]))
        pages += 1
        cursor = data.get("cursor")
        if not cursor:
            exhausted = True
            break
    record(result, kind, handles, expected, exhausted, error=error)


platform = registry.register(registry.Platform(
    key="bluesky",
    label="Bluesky",
    homepage="https://bsky.app",
    url="https://bsky.app/profile/{handle}",
    capabilities=CAPABILITIES,
    login="none",
    browser=False,
    collect=collect,
))

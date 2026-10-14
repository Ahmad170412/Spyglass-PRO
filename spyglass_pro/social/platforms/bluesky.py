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

    labels = [label.get("val") for label in (profile.get("labels") or [])
              if isinstance(label, dict) and label.get("val")]
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
                "actor": handle, "limit": "12", "filter": "posts_no_replies",
            })
            if feed is not None:
                normalize_feed(feed.get("feed"), profile.get("handle") or handle, result)
            else:
                add_note(result, "recent posts unavailable (feed endpoint failed)")
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

"""Post extraction + normalization (modern 2026+ and legacy GraphQL shapes).

Each post page embeds its own full node (code, caption, counts, media
candidates, usertags, location, comments). `visit_post` walks one post page
like a human would, then `norm_post` flattens whatever shape the page served
onto the report's stable post schema.
"""

from __future__ import annotations

import random
from pathlib import Path

from .fetch import download_media
from .human import dismiss_login_popup, human_delay, human_scroll
from .jsonutil import deep_find, extract_json_blobs, iter_dicts
from .jsonutil import first as _first
from .jsonutil import first_present as _present


def _caption_text(node: dict) -> str:
    """Normalize a caption from any of Instagram's shapes into plain text."""
    cap = node.get("caption")
    if isinstance(cap, str):
        return cap
    if isinstance(cap, dict):
        t = cap.get("text")
        return t if isinstance(t, str) else ""
    if isinstance(cap, list):
        parts = []
        for item in cap:
            if isinstance(item, dict):
                t = item.get("text")
                if isinstance(t, str):
                    parts.append(t)
                else:
                    n = item.get("node")
                    if isinstance(n, dict) and isinstance(n.get("text"), str):
                        parts.append(n["text"])
            elif isinstance(item, str):
                parts.append(item)
        return "".join(parts)
    # legacy graphql edge shape
    return "".join((e.get("node") or {}).get("text", "")
                    for e in ((node.get("edge_media_to_caption") or {}).get("edges") or []))


def _best_image_url(node: dict) -> str | None:
    cands = ((node.get("image_versions2") or {}).get("candidates")) or []
    best = None
    for c in cands:
        if not c.get("url"):
            continue
        if best is None or (c.get("width") or 0) * (c.get("height") or 0) > \
                (best.get("width") or 0) * (best.get("height") or 0):
            best = c
    if best:
        return best["url"]
    return node.get("display_url") or node.get("display_src")


def _best_video_url(node: dict) -> str | None:
    vv = node.get("video_versions") or []
    if vv and vv[0].get("url"):
        return vv[0]["url"]
    return node.get("video_url")


def _media_items(node: dict) -> list[dict]:
    """Media entries ({type, url}) for modern + legacy node shapes."""
    out: list[dict] = []
    carousel = node.get("carousel_media") or []
    if carousel:
        for child in carousel:
            if isinstance(child, dict):
                out.extend(_media_items(child))
        return out

    is_vid = bool(node.get("is_video") or node.get("video_versions")
                  or node.get("video_url") or node.get("media_type") == 2)
    if is_vid:
        v = _best_video_url(node)
        if v:
            out.append({"type": "video", "url": v})
    else:
        v = _best_image_url(node)
        if v:
            out.append({"type": "image", "url": v})

    # legacy carousel edge shape
    for e in ((node.get("edge_sidecar_to_children") or {}).get("edges") or []):
        ch = e.get("node") or {}
        out.append({"type": "video" if ch.get("is_video") else "image",
                    "url": ch.get("video_url") or ch.get("display_url")})

    seen: set[str] = set()
    dedup: list[dict] = []
    for m in out:
        if m["url"] and m["url"] not in seen:
            seen.add(m["url"])
            dedup.append(m)
    return dedup


def norm_post(node: dict) -> dict:
    """Normalize a post node from modern (2026+) or legacy shapes."""
    def edges(key: str) -> list:
        return ((node.get(key) or {}).get("edges")) or []

    location_raw = node.get("location")
    location = None
    if isinstance(location_raw, dict):
        location = {
            "name": location_raw.get("name"),
            "short_name": location_raw.get("short_name"),
            "city": location_raw.get("city"),
            "country": location_raw.get("country"),
            "address": location_raw.get("address_json"),
        }

    tagged: list[str] = []
    for u in (node.get("usertags") or {}).get("in") or []:
        un = (u.get("user") or {}).get("username") if isinstance(u, dict) else None
        if un:
            tagged.append(un)
    for e in edges("edge_media_to_tagged_user"):
        un = (e.get("node") or {}).get("user", {}).get("username")
        if un:
            tagged.append(un)

    owner = node.get("user")
    comments = [
        {"username": (e.get("node") or {}).get("owner", {}).get("username"),
         "text": (e.get("node") or {}).get("text")}
        for e in edges("edge_media_to_parent_comment")[:15]
        if (e.get("node") or {}).get("owner")
    ]

    return {
        "shortcode": node.get("code") or node.get("shortcode"),
        "id": _first(node.get("id"), node.get("pk")),
        "owner_username": (owner or {}).get("username") if isinstance(owner, dict) else None,
        "timestamp": _first(node.get("taken_at"), node.get("taken_at_timestamp")),
        "media_type": node.get("media_type"),
        "is_video": bool(node.get("is_video") or node.get("video_versions")
                         or node.get("media_type") == 2),
        "caption": _caption_text(node).strip(),
        "likes": _present(node.get("like_count"),
                          ((node.get("edge_media_preview_like") or {}).get("count"))),
        "comments_count": _present(node.get("comment_count"),
                                   ((node.get("edge_media_to_comment") or {}).get("count"))),
        "video_views": _present(node.get("video_view_count"), node.get("play_count")),
        "location": location,
        "media": _media_items(node),
        "tagged_users": tagged,
        "comments": comments,
    }


_POST_CONTENT_KEYS = ("caption", "like_count", "comment_count", "media_type",
                       "image_versions2", "video_versions", "taken_at", "location",
                       "usertags", "carousel_media", "user", "video_url", "display_url")


def _post_score(node: dict) -> int:
    """How much real post content a dict carries (stubs score ~0)."""
    return sum(1 for k in _POST_CONTENT_KEYS
               if k in node and node[k] not in (None, [], {}))


def find_post_in_blobs(blobs: list, shortcode: str) -> dict | None:
    """Find the full post node inside Instagram's embedded JSON blobs.

    Post pages embed several dicts that mention the shortcode (preview
    stubs, navigation state). We pick the one with the most real content.
    """
    best, best_score = None, 2
    for blob in blobs:
        for d in iter_dicts(blob):
            if d.get("code") == shortcode or d.get("shortcode") == shortcode:
                s = _post_score(d)
                if s > best_score:
                    best, best_score = d, s
    if best:
        return norm_post(best)
    # legacy deep-search fallback
    for blob in blobs:
        node = deep_find(blob, "shortcode", "display_url")
        if node and node.get("shortcode") == shortcode:
            return norm_post(node)
    return None


def post_from_embedded(page, shortcode: str) -> dict | None:
    try:
        html = page.content()
    except Exception:
        return None
    return find_post_in_blobs(extract_json_blobs(html), shortcode)


def shortcodes_from_dom(page, username: str) -> list[str]:
    """Collect post shortcodes from the rendered profile grid links.

    Logged-out grids render posts as /{user}/p|reel|tv/{shortcode}/ links.
    Used when the profile API (which returns ~12 recent posts) is throttled.
    """
    js = """(u) => {
        const out = [];
        const seen = new Set();
        const re = new RegExp('^/' + u + '/(p|reel|tv)/([A-Za-z0-9_-]+)/?$');
        document.querySelectorAll('a[href]').forEach(a => {
            const h = a.getAttribute('href') || '';
            const m = h.match(re);
            if (m && !seen.has(m[2])) { seen.add(m[2]); out.push(m[2]); }
        });
        return out;
    }"""
    try:
        return page.evaluate(js, username) or []
    except Exception:
        return []


def visit_post(page, cfg: dict, shortcode: str, out_dir: Path) -> dict | None:
    url = f"https://www.instagram.com/p/{shortcode}/"
    try:
        page.goto(url, wait_until="domcontentloaded", timeout=45000)
    except Exception:
        return None
    human_delay(cfg, 1.5, 3.0)
    dismiss_login_popup(page)
    # organic dwell: a little scroll through the post
    if random.random() < 0.7:
        human_scroll(page, random.randint(250, 700))
    post = post_from_embedded(page, shortcode)
    if post is None:
        return None
    if cfg["download_media"]:
        post["media_files"] = []
        for i, m in enumerate(post["media"]):
            if m["type"] == "video" and not cfg["download_videos"]:
                continue
            fname = f"{shortcode}_{i}" if len(post["media"]) > 1 else shortcode
            path = download_media(page, m["url"], out_dir, fname)
            if path:
                m["path"] = path
                post["media_files"].append(path)
    return post

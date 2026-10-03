"""Logged-in story tray scrape (stories expire after 24h)."""

from __future__ import annotations

from pathlib import Path

from .fetch import INSTAGRAM_APP_ID, download_media

REEL_API = "https://i.instagram.com/api/v1/feed/user/{pk}/reel_media/"
REEL_API_FALLBACK = "https://www.instagram.com/api/v1/feed/user/{pk}/reel_media/"


def parse_stories(items: list) -> list:
    """Normalize the story tray API items."""
    out = []
    for it in items:
        if not isinstance(it, dict):
            continue
        cands = ((it.get("image_versions2") or {}).get("candidates") or [])
        imgs = [c.get("url") for c in cands if c.get("url")]
        vids = [v.get("url") for v in (it.get("video_versions") or []) if v.get("url")]
        # For video stories put the mp4 first so downloaders grab the real
        # file (with audio), not the poster frame.
        urls = (vids + imgs) if it.get("media_type") == 2 else (imgs + vids)
        out.append({
            "id": it.get("pk"),
            "taken_at": it.get("taken_at"),
            "expiring_at": it.get("expiring_at"),
            "media_type": it.get("media_type"),
            "urls": urls,
        })
    return out


def collect_stories(page, pk: str, media_dir: Path, download: bool = False) -> dict | None:
    """Best-effort logged-in story scrape (stories expire after 24h)."""
    headers = {"x-ig-app-id": INSTAGRAM_APP_ID}
    for u in (REEL_API.format(pk=pk), REEL_API_FALLBACK.format(pk=pk)):
        try:
            resp = page.request.get(u, headers=headers, timeout=30000)
            if resp.ok:
                items = (resp.json() or {}).get("items") or []
                entries = parse_stories(items)
                if download and media_dir:
                    for e in entries:
                        if e.get("urls"):
                            fn = download_media(page, e["urls"][0],
                                                media_dir / "stories",
                                                f"story_{e.get('id', 'x')}")
                            if fn:
                                e["file"] = fn
                return {"count": len(entries), "items": entries}
        except Exception:  # noqa: S112 - try the next story batch
            continue
    return None

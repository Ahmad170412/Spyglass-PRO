"""Instagram adapter — delegates to the proven InstaCloak engine.

Instagram already has a full, tested collection path (posts, media,
stories, follower lists, contacts). Rather than reimplement it against the
normalized schema and risk regressions, this adapter runs the existing
engine and translates its report.

The one thing it deliberately does not do is reuse InstaCloak's browser
session: :mod:`spyglass_pro.social.harness` owns the session so every
platform shares one lifecycle, so this calls the engine's collection
steps directly with the page it was handed.
"""

from __future__ import annotations

import time

from .. import registry
from ..lists import record as record_list
from ..schema import add_note, set_fields

# What this platform can actually return, from the engine's own feature set.
CAPABILITIES = (
    "profile", "bio", "followers", "following", "post_count", "posts",
    "avatar", "verified", "private", "media", "stories", "contacts",
)


def normalize(report: dict, result: dict) -> None:
    """Map an InstaCloak report onto the normalized schema.

    Pure and offline-testable: no browser, no network.
    """
    profile = report.get("profile") or {}
    if not profile:
        return
    result["found"] = True

    # norm_profile nests the counters under "counts"; older shapes put them
    # at the top level, so read both rather than rendering a blank cell.
    counts = profile.get("counts") or {}

    def count(name):
        value = counts.get(name)
        if value is None:
            value = profile.get(name)
        return value

    set_fields(
        result,
        display_name=profile.get("full_name"),
        bio=profile.get("biography"),
        url=profile.get("profile_url") or result.get("url"),
        follower_count=count("followers"),
        following_count=count("following"),
        post_count=count("posts"),
        verified=bool(profile.get("is_verified")),
        private=bool(profile.get("is_private")),
        avatar_url=profile.get("profile_pic") or profile.get("profile_pic_url"),
        external_links=(profile.get("external_url") and [profile["external_url"]]) or [],
        contact_email=profile.get("business_email") or profile.get("public_email"),
    )

    if counts:
        result.setdefault("metrics", {})
        result["metrics"].update({k: v for k, v in counts.items() if v is not None})

    posts = report.get("posts") or []
    result["posts"] = [
        {
            "id": post.get("shortcode") or post.get("id"),
            "url": post.get("url"),
            "caption": post.get("caption"),
            "media_type": post.get("media_type"),
            "likes": post.get("likes"),
            "comments": post.get("comment_count"),
            "timestamp": post.get("timestamp"),
            "location": (post.get("location") or {}).get("name"),
            # Keep each post's downloaded files beside the post itself. A
            # flat media list cannot answer "which images belong to this
            # post", and the dashboard's per-check media view needs exactly
            # that. Older snapshots simply have no key.
            "media_files": [str(f) for f in (post.get("media_files") or []) if f],
        }
        for post in posts if isinstance(post, dict)
    ]
    result["media_files"] = list(report.get("media_files") or [])

    # Story tray capture. The engine hands back {"count", "items"}; store
    # the metadata the dashboard can render later (the CDN URLs expire, so
    # only the local file path is worth keeping). None means "stories were
    # not captured this check", not "this account had none".
    stories = report.get("stories")
    if isinstance(stories, dict):
        items = []
        for item in stories.get("items") or []:
            if not isinstance(item, dict):
                continue
            items.append({
                "id": item.get("id"),
                "taken_at": item.get("taken_at"),
                "expiring_at": item.get("expiring_at"),
                "media_type": item.get("media_type"),
                "file": item.get("file") or None,
            })
        result["stories"] = {"count": stories.get("count", len(items)),
                             "items": items}
    elif stories is not None:
        result["stories"] = None

    for kind, key in (("followers", "followers"), ("following", "following")):
        # build_report hands back {count, collected, walled, usernames};
        # a bare list is the shape the offline fixtures (and older
        # reports) use. Reading the dict as a list counted its own four
        # keys — every note said "4 followers retrieved".
        block = report.get(key)
        if isinstance(block, dict):
            retrieved = block.get("usernames") or []
            walled = bool(block.get("walled"))
        else:
            retrieved = block or []
            walled = False
        skipped = bool(report.get(f"{key}_skipped") or report.get("lists_skipped"))
        expected = result.get("follower_count" if key == "followers" else "following_count")
        handles = [u.get("username") if isinstance(u, dict) else u for u in retrieved]
        handles = [h for h in handles if h]
        if not handles:
            why = ("login-walled — a burner login unlocks it"
                   if (skipped or walled) else "not retrievable for this account")
            record_list(result, kind, [], expected, False, error=why)
            continue
        # The modal is a sample (the engine's max_followers window, with
        # no proof the list ended), so exhausted=False: lists.record keeps
        # it incomplete unless the walk reached the profile counter — and
        # "5 of 686M" stays a labelled partial, never a bare number.
        record_list(result, kind, handles, expected, False)
        partial = bool(skipped or walled)
        result.setdefault("metrics", {})[f"{key}_retrieved"] = len(handles)
        add_note(result, f"{len(handles)} {kind} retrieved"
                         + (" (partial — the rest is login-walled)" if partial else ""))

    if report.get("contacts"):
        result["contacts"] = report["contacts"]
    for note in report.get("notes") or []:
        add_note(result, note)


def collect(page, cfg, handle: str, result: dict) -> None:
    """Run InstaCloak's collection steps against the harness's page.

    Mirrors ``instacloak.engine.collect`` step for step, minus the session
    launch (the harness owns that) and the console UI (the harness collects
    progress). Keeping the sequence identical is the point: this adapter is
    a re-wiring, not a re-implementation.
    """
    import re as _re
    from pathlib import Path

    from instacloak.fetch import download_media
    from instacloak.human import dismiss_login_popup, human_delay, warmup_scrolls
    from instacloak.post import shortcodes_from_dom, visit_post
    from instacloak.profile import _hd_propic_url, get_profile, norm_profile, profile_from_embedded
    from instacloak.report import build_report
    from instacloak.session import safe_dir_name
    from instacloak.social import attempt_relationship_list
    from instacloak.stories import collect_stories

    logged_in = bool(result.get("logged_in"))
    deep = bool(cfg.get("deep"))
    max_posts = int(cfg.get("max_posts") or 0)
    out_dir = Path(cfg["output_dir"]) / safe_dir_name(handle)
    media_dir = out_dir / "media"
    media_dir.mkdir(parents=True, exist_ok=True)

    try:
        page.goto(f"https://www.instagram.com/{handle}/",
                  wait_until="domcontentloaded", timeout=60000)
        page.wait_for_timeout(2500)
    except Exception as exc:
        result["error"] = f"could not reach instagram.com: {_flat(exc)[:140]}"
        return
    dismiss_login_popup(page)
    warmup_scrolls(page)

    profile_raw, source = get_profile(page, handle)
    if profile_raw is None:
        profile_raw = profile_from_embedded(page, handle)
        source = "dom_page" if profile_raw is not None else source
    if profile_raw is None:
        result["error"] = (f"Instagram returned no profile for @{handle} "
                           f"(reason: {source or 'unavailable'})")
        return

    profile = norm_profile(profile_raw)
    result["source"] = source

    notes: list[str] = []
    if profile.get("is_private"):
        notes.append("private account: posts, followers list, and media are not available")

    stories = None
    if logged_in and profile.get("id"):
        # "Download Media" is the dashboard's explicit yes to keeping files;
        # deep mode implied it before this flag existed. Honour either.
        stories = collect_stories(page, str(profile["id"]), media_dir,
                                  bool(deep or cfg.get("download_media")))
        if not (stories and stories.get("count")):
            notes.append("stories unavailable (API blocked or no active stories)")

    posts: list[dict] = []
    media_files: list[str] = []
    if not profile.get("is_private"):
        shortcodes = [p.get("shortcode") for p in profile.get("recent_posts", [])
                      if p.get("shortcode")]
        if len(shortcodes) < max_posts:
            for shortcode in shortcodes_from_dom(page, handle):
                if shortcode not in shortcodes:
                    shortcodes.append(shortcode)
                if len(shortcodes) >= max_posts:
                    break
        shortcodes = shortcodes[:max_posts]
        if not shortcodes:
            notes.append("no post shortcodes found (profile API throttled and "
                         "grid empty — retry later or use a residential proxy)")
        for shortcode in shortcodes:
            post = visit_post(page, cfg, shortcode, media_dir)
            if post:
                posts.append(post)
                media_files.extend(post.get("media_files", []))
            human_delay(cfg, 1.8, 3.6)

        if deep:
            pic = profile.get("profile_pic_url") or ""
            saved = (download_media(page, _hd_propic_url(pic), media_dir, "propic_hd")
                     or download_media(page, pic, media_dir, "propic"))
            if saved:
                profile["profile_pic_file"] = saved
                media_files.append(saved)
            for highlight in profile.get("highlights", []):
                if highlight.get("cover_url"):
                    stem = (_re.sub(r"[^\w\-]+", "_", highlight["title"]).strip("_")
                            or "highlight")
                    fn = download_media(page, highlight["cover_url"],
                                        media_dir / "highlights", stem)
                    if fn:
                        highlight["cover_file"] = fn
                        media_files.append(fn)

    followers: tuple = ([], True)
    following: tuple = ([], True)
    if cfg.get("attempt_followers") and not profile.get("is_private"):
        followers = attempt_relationship_list(page, cfg, handle, "followers")
        following = attempt_relationship_list(page, cfg, handle, "following")

    report = build_report(cfg, handle, profile, source, posts, followers, following,
                          media_files, notes, time.time(), stories=stories,
                          lists_skipped=bool(followers[1] or following[1]))
    normalize(report, result)


def _flat(exc) -> str:
    return " ".join(str(exc).split())


platform = registry.register(registry.Platform(
    key="instagram",
    label="Instagram",
    homepage="https://instagram.com",
    url="https://www.instagram.com/{handle}/",
    capabilities=CAPABILITIES,
    login="instacloak",
    collect=collect,
))

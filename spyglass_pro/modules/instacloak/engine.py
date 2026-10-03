"""The OSINT run orchestration (`collect`) — wires every module together.

This is the only place that knows the *sequence* of a run:
launch -> login? -> profile -> stories? -> posts/media -> social graph -> report.
Each step lives in its own module; this file just drives them in order and
keeps the run honest (notes + graceful degradation on every wall/block).
"""

from __future__ import annotations

import json
import random
import re
import time
from pathlib import Path

from .auth import ensure_login
from .fetch import download_media
from .human import dismiss_login_popup, human_delay, warmup_scrolls
from .post import shortcodes_from_dom, visit_post
from .profile import _hd_propic_url, get_profile, norm_profile, profile_from_dom, profile_from_embedded
from .report import build_report, write_report
from .session import open_session, safe_dir_name
from .social import attempt_relationship_list
from .stories import collect_stories
from .ui import say, say_parts, section


def _list_wall_note(kind: str, profile: dict | None, logged_in: bool) -> tuple[str, str]:
    """Why a list came back walled -- label + note copy for the report."""
    if profile and profile.get("is_private"):
        label = "private account"
        why = (f"{kind} list not visible: private account "
               "(viewable only after the burner follows them)")
    elif not logged_in:
        label = "login-walled"
        why = f"{kind} list login-walled (unlocks via burner login)"
    else:
        label = "walled"
        why = f"{kind} list unavailable (session could not unlock it)"
    return label, why


def output_dir(cfg: dict, username: str) -> Path:
    """Resolve a target's output directory (dir name is a sanitized slug)."""
    return Path(cfg["output_dir"]) / safe_dir_name(username)


def collect(cfg: dict, username: str) -> dict:
    started = time.time()
    notes: list[str] = []
    # `username` is used raw for URLs and the report; dirs get a sanitized slug
    out_dir = output_dir(cfg, username)
    media_dir = out_dir / "media"
    out_dir.mkdir(parents=True, exist_ok=True)

    section(1, 5, f"launching stealth browser for @{username}")
    ctx = open_session(cfg, safe_dir_name(username))
    page = ctx.new_page()

    logged_in = False
    if cfg.get("login_enabled") and cfg.get("login_username") and cfg.get("login_password"):
        logged_in = ensure_login(page, cfg, username)
        if logged_in:
            notes.append(f"session logged in as @{cfg['login_username']}")
        else:
            notes.append("burner login unavailable -- continuing logged-out")

    try:
        section(2, 5, "visiting profile (warm-up scrolls first)")
        try:
            page.goto(f"https://www.instagram.com/{username}/",
                      wait_until="domcontentloaded", timeout=60000)
        except Exception as exc:
            say(f"  page load failed: {exc}", "yellow")
        human_delay(cfg, 2.0, 4.0)
        warmup_scrolls(page, n=random.randint(2, 4))
        dismiss_login_popup(page)

        say("  pulling profile data...")
        profile_raw, reason = get_profile(page, username)
        if profile_raw is None:
            profile_raw = profile_from_embedded(page, username)
            if profile_raw:
                reason = "embedded_page_json"
        if profile_raw is None:
            profile_raw = profile_from_dom(page, username)
            if profile_raw:
                reason = "dom_page"
                notes.append("profile API throttled; basics scraped from the visible page")
        if profile_raw is None:
            reason = reason or "not_found"
            say(f"  profile unavailable ({reason}). "
                "Private account, or Instagram is login-walling this IP.", "yellow")
            notes.append(f"profile unavailable: {reason}")
            # Persist even the degraded report — an empty output dir with no
            # report.json is how failed runs used to vanish silently.
            report = build_report(cfg, username, None, reason, [], ([], True),
                                  ([], True), [], notes, started)
            report_path = write_report(report, out_dir)
            say_parts("  saved: ", (str(report_path), "green"))
            return report

        profile = profile_raw if reason == "dom_page" else norm_profile(profile_raw)
        if profile.get("is_private"):
            say("  target is private — public data is limited to the basics.", "yellow")
            notes.append("private account: posts, followers list, and media are not available")

        stories = None
        if logged_in and profile.get("id"):
            say("  pulling stories (logged-in)...")
            stories = collect_stories(page, str(profile["id"]), media_dir,
                                      bool(cfg.get("deep")))
            if stories and stories.get("count"):
                say(f"  stories: {stories['count']} available (24h window)", "green")
            else:
                notes.append("stories unavailable (API blocked or no active stories)")

        posts: list[dict] = []
        media_files: list[str] = []
        if not profile.get("is_private"):
            section(3, 5, "extracting posts and media")
            shortcodes = [p.get("shortcode") for p in profile.get("recent_posts", [])
                          if p.get("shortcode")]
            if len(shortcodes) < int(cfg["max_posts"]):
                # API throttled/limited? pull what the rendered grid shows
                grid_sc = shortcodes_from_dom(page, username)
                for sc in grid_sc:
                    if sc not in shortcodes:
                        shortcodes.append(sc)
                    if len(shortcodes) >= int(cfg["max_posts"]):
                        break
            shortcodes = shortcodes[: int(cfg["max_posts"])]
            if not shortcodes:
                notes.append("no post shortcodes found (profile API throttled and "
                             "grid empty -- retry later or use a residential proxy)")
            say(f"  {len(shortcodes)} recent post(s) to visit (logged-out shows ~12)")
            for i, sc in enumerate(shortcodes, 1):
                say(f"  [{i}/{len(shortcodes)}] visiting post {sc}")
                post = visit_post(page, cfg, sc, media_dir)
                if post:
                    posts.append(post)
                    media_files.extend(post.get("media_files", []))
                human_delay(cfg, 1.8, 3.6)

            if cfg.get("deep"):
                say("  deep mode: profile picture + highlight covers", "magenta")
                pic = profile.get("profile_pic_url") or ""
                saved = (download_media(page, _hd_propic_url(pic), media_dir, "propic_hd")
                         or download_media(page, pic, media_dir, "propic"))
                if saved:
                    profile["profile_pic_file"] = saved
                    media_files.append(saved)
                for h in profile.get("highlights", []):
                    if h.get("cover_url"):
                        stem = re.sub(r"[^\w\-]+", "_", h["title"]).strip("_") or "highlight"
                        fn = download_media(page, h["cover_url"],
                                            media_dir / "highlights", stem)
                        if fn:
                            h["cover_file"] = fn
                            media_files.append(fn)

        skipped = not cfg["attempt_followers"]
        if not skipped:
            section(4, 5, "checking social graph (followers / following)")
            f_list, f_walled = attempt_relationship_list(page, cfg, username, "followers")
            g_list, g_walled = attempt_relationship_list(page, cfg, username, "following")
            for kind, lst, walled in (("followers", f_list, f_walled),
                                      ("following", g_list, g_walled)):
                if walled:
                    label, why = _list_wall_note(kind, profile, logged_in)
                    notes.append(why)
                    say(f"  {kind}: collected {len(lst)} [{label}]")
                else:
                    say(f"  {kind}: collected {len(lst)}")
                human_delay(cfg, 1.5, 3.0)
        else:
            # Skipped, not walled: we never tried, so `walled` must stay False.
            # Claiming a wall we did not hit is exactly the kind of invented
            # data this tool promises never to produce.
            f_list, g_list, f_walled, g_walled = [], [], False, False
            notes.append("followers/following lists not attempted "
                         "(--no-followers) -- 'walled' is false, not walled")
            say("  social graph skipped (--no-followers)", "yellow")

        section(5, 5, "writing report")
        report = build_report(cfg, username, profile, "ok", posts,
                              (f_list, f_walled), (g_list, g_walled),
                              media_files, notes, started,
                              lists_skipped=skipped, stories=stories)
        raw_path = out_dir / "raw_profile.json"
        raw_path.write_text(json.dumps(profile_raw, indent=2, ensure_ascii=False),
                            encoding="utf-8")
        report_path = write_report(report, out_dir)
        say_parts("  saved: ", (str(report_path), "green"))
        return report
    finally:
        try:
            ctx.close()
        except Exception:
            pass

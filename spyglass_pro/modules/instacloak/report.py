"""Report assembly (build_report), writing, and rendering (terminal + markdown)."""

from __future__ import annotations

import json
import re
import time
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .contacts import HASHTAG_RE, MENTION_RE, collect_contacts, count_matches
from .ui import say, say_parts


def _tri(v) -> str:
    """Render a tri-state (True/False/None) field; None means 'not served'."""
    return "unknown (not served logged-out)" if v is None else str(v)


def _contact_channels(p: dict) -> str:
    chans = []
    if p.get("business_email"):
        chans.append("email")
    if p.get("business_phone_number"):
        chans.append("phone")
    return f" ({', '.join(chans)})" if chans else ""


def build_report(cfg: dict, username: str, profile: dict | None, reason: str,
                 posts: list[dict], followers: tuple[list, bool],
                 following: tuple[list, bool], media_files: list[str],
                 notes: list[str], started: float, lists_skipped: bool = False,
                 stories: dict | None = None) -> dict:
    all_texts = [profile.get("biography") or ""] if profile else []
    all_texts += [p.get("caption") or "" for p in posts]

    commenters: dict[str, int] = {}
    for p in posts:
        for cm in p.get("comments", []):
            u = cm.get("username")
            if u:
                commenters[u.lower()] = commenters.get(u.lower(), 0) + 1

    tagged: list[str] = []
    for p in posts:
        for t in p.get("tagged_users", []):
            if t and t.lower() not in tagged:
                tagged.append(t.lower())

    locations = []
    for p in posts:
        loc = p.get("location")
        if loc and loc.get("name") and loc["name"] not in locations:
            locations.append(loc)

    contacts = collect_contacts(profile or {}, posts)

    f_list, f_walled = followers
    g_list, g_walled = following

    # Patch: if Instagram nulled the post count, use what we actually visited
    if profile and (profile.get("counts") or {}).get("posts") is None and posts:
        profile["counts"]["posts"] = len(posts)

    return {
        "tool": "InstaCloak",
        "version": __version__,
        "target": username,
        "run_at": datetime.now(timezone.utc).isoformat(),
        "duration_seconds": round(time.time() - started, 1),
        "profile_status": "ok" if profile else reason,
        "profile": profile,
        "posts_count": len(posts),
        "posts": posts,
        "contacts": contacts,
        "hashtags": dict(sorted(count_matches(all_texts, HASHTAG_RE).items(),
                                key=lambda kv: -kv[1])),
        "mentions": dict(sorted(count_matches(all_texts, MENTION_RE).items(),
                                key=lambda kv: -kv[1])),
        "locations": locations,
        "commenters": dict(sorted(commenters.items(), key=lambda kv: -kv[1])),
        "tagged_users": tagged,
        "followers": {
            "count": (profile or {}).get("counts", {}).get("followers"),
            "collected": len(f_list),
            "walled": f_walled,
            "skipped": lists_skipped,
            "usernames": f_list,
        },
        "following": {
            "count": (profile or {}).get("counts", {}).get("following"),
            "collected": len(g_list),
            "walled": g_walled,
            "skipped": lists_skipped,
            "usernames": g_list,
        },
        "media_downloaded": media_files,
        "notes": notes,
        "stories": stories,
    }


def write_report(report: dict, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "report.json"
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# Markdown export
# ---------------------------------------------------------------------------

_MD_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _md_clean(text: object) -> str:
    """Unicode-safe single-line text without control chars."""
    s = str(text)
    s = _MD_CTRL_RE.sub("", s)
    return re.sub(r"\s+", " ", s).strip()


def _md_cell(text: object) -> str:
    """Table-cell safe: single line, pipe and backslash escaped."""
    return _md_clean(text).replace("\\", "\\\\").replace("|", "\\|")


def _dt(ts) -> str | None:
    """Unix timestamp -> 'YYYY-MM-DD HH:MM UTC' (or None)."""
    if not isinstance(ts, (int, float)):
        return None
    try:
        return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    except (OverflowError, OSError, ValueError):
        return None


def _profile_md(report: dict, p: dict) -> list[str]:
    counts = p.get("counts") or {}
    lines = ["## Profile", "", "| field | value |", "|---|---|",
             f"| username | {_md_cell(p.get('username'))} |",
             f"| full name | {_md_cell(p.get('full_name') or '—')} |",
             f"| followers | {counts.get('followers')} |",
             f"| following | {counts.get('following')} |",
             f"| posts | {counts.get('posts')} |",
             f"| private | {p.get('is_private')} |",
             f"| verified | {p.get('is_verified')} |",
             f"| business | {_tri(p.get('is_business'))} |"]
    if p.get("business_category"):
        lines.append(f"| category | {_md_cell(p.get('business_category'))} |")
    exposed = p.get("business_contact_exposed")
    if exposed is not None:
        label = "yes" if exposed else "no"
        lines.append(f"| contact button | {label}{_contact_channels(p)} |")
    if p.get("id"):
        lines.append(f"| user id | {_md_cell(p.get('id'))} |")
    if p.get("is_joined_recently"):
        lines.append("| account age | **new** (joined recently badge) |")
    badges = p.get("account_badges") or []
    if badges:
        lines.append(f"| badges | {_md_cell(', '.join(str(b) for b in badges))} |")
    if p.get("last_reel_at"):
        lines.append(f"| last reel | {_md_clean(p['last_reel_at'])} |")
    if p.get("pronouns"):
        lines.append(f"| pronouns | {_md_cell(', '.join(p['pronouns']))} |")
    bio = p.get("biography")
    if bio:
        lines += ["", f"> {_md_cell(bio)}"]
    links = p.get("bio_links") or []
    if links:
        lines += ["", "**Links**"]
        for bl in links:
            title = _md_clean(bl.get("title") or bl.get("url"))
            lines.append(f"- [{title}]({_md_clean(bl.get('url'))})")
            if bl.get("is_pinned"):
                lines.append("  - *(pinned)*")
    hl = p.get("highlights") or []
    if hl:
        lines += ["", "**Highlight stories**"]
        for h in hl:
            lines.append(f"- {_md_clean(h.get('title'))}")
    rel = p.get("related_profiles") or []
    if rel:
        lines += ["", f"**Similar accounts:** {_md_clean(', '.join(rel))}"]
    if p.get("is_memorialized"):
        lines += ["", "*This account is memorialized (deceased user).*", ""]
    lines.append("")
    return lines


def _contacts_md(contacts: dict) -> list[str]:
    lines = ["## Contacts", ""]
    if not any([contacts.get("emails"), contacts.get("phones")]):
        return [*lines, "None found.", ""]
    if contacts.get("emails"):
        lines += ["**Emails**"]
        for i, e in enumerate(contacts["emails"]):
            src = contacts.get("sources") or []
            tag = f" *(source: {src[i]})" if i < len(src) else ""
            lines.append(f"- {_md_clean(e)}{tag}")
        lines.append("")
    if contacts.get("phones"):
        lines += ["**Phones**"]
        for i, ph in enumerate(contacts["phones"]):
            src = contacts.get("sources") or []
            tag = f" *(source: {src[i]})" if i < len(src) else ""
            lines.append(f"- {_md_clean(ph)}{tag}")
        lines.append("")
    return lines


def _tag_md(title: str, mapping: dict) -> list[str]:
    lines = [f"## {title}", ""]
    if not mapping:
        return [*lines, "None.", ""]
    lines += ["| tag | count |", "|---|---|"]
    for tag, n in mapping.items():
        lines.append(f"| {_md_cell(tag)} | {n} |")
    lines.append("")
    return lines


def _posts_md(report: dict) -> list[str]:
    posts = report.get("posts") or []
    lines = [f"## Posts ({len(posts)} deep-visited)", ""]
    if not posts:
        return [*lines, "None collected.", ""]
    for i, post in enumerate(posts, 1):
        sc = post.get("shortcode")
        lines += [f"### {i}. {_md_clean(sc or '(no shortcode)')}", ""]
        if sc:
            lines.append(f"**Link:** https://www.instagram.com/p/{_md_clean(sc)}/")
        caption = (post.get("caption") or "").strip()
        if caption:
            lines.append("")
            lines.append(f"> {_md_cell(caption)}")
        meta = []
        ts = _dt(post.get("timestamp"))
        if ts:
            meta.append(f"posted {ts}")
        meta.append(f"{post.get('likes')} likes")
        meta.append(f"{post.get('comments_count')} comments")
        if post.get("is_video"):
            meta.append(f"{post.get('video_views')} views")
        lines += ["", "*" + " · ".join(meta) + "*"]
        loc = post.get("location")
        if loc and loc.get("name"):
            lines.append(f"- **Location:** {_md_cell(loc.get('name'))}"
                         f"{(' · ' + _md_clean(loc.get('city'))) if loc.get('city') else ''}")
        if post.get("tagged_users"):
            lines.append(f"- **Tagged:** {_md_cell(', '.join('@' + u for u in post['tagged_users']))}")
        media = post.get("media") or []
        if media:
            kinds = [m.get("type") for m in media]
            lines.append(f"- **Media:** {len(media)} item(s) — {_md_cell(', '.join(k for k in kinds if k))}")
        files = post.get("media_files") or []
        for f in files:
            lines.append(f"  - saved: `{_md_cell(f)}`")
        comments = post.get("comments") or []
        if comments:
            lines.append("- **Comments:**")
            for cm in comments:
                who = _md_clean(cm.get("username"))
                text = _md_cell(cm.get("text"))[:200]
                lines.append(f"  - **@{who}:** {text}")
        lines.append("")
    return lines


def _wall_label(report: dict, g: dict) -> str:
    """Suffix explaining an empty list: skipped vs private vs login wall."""
    if g.get("skipped"):
        return " (not attempted -- --no-followers)"
    if not g.get("walled"):
        return ""
    if (report.get("profile") or {}).get("is_private"):
        return " (private account)"
    return " (login-walled)"


def _social_md(report: dict) -> list[str]:
    lines = ["## Social graph", ""]
    for label, key in (("Followers", "followers"), ("Following", "following")):
        g = report.get(key) or {}
        n = g.get("count")
        lines.append(f"- **{label}:** count={n}, collected={g.get('collected')}"
                     + _wall_label(report, g))
        for u in (g.get("usernames") or [])[:50]:
            lines.append(f"  - @{_md_clean(u)}")
    return [*lines, ""]


def render_markdown(report: dict) -> str:
    """Render the whole report as a readable Markdown document."""
    target = report.get("target", "?")
    status = report.get("profile_status")
    out = [f"# InstaCloak report — @{_md_clean(target)}", "",
           f"*Generated {_md_clean(report.get('run_at'))} · "
           f"{report.get('tool')} v{report.get('version')} · "
           f"{report.get('duration_seconds')}s · status: {status}*", ""]
    if status == "ok":
        out += _profile_md(report, report.get("profile") or {})
    else:
        out += ["## Profile", "", f"*Unavailable — {_md_clean(status)}.*", ""]
    out += _contacts_md(report.get("contacts") or {})
    out += _tag_md("Hashtags", report.get("hashtags") or {})
    out += _tag_md("Mentions", report.get("mentions") or {})
    locs = report.get("locations") or []
    out += ["## Locations", ""] + (
        [f"- {_md_cell(loc['name'])}" for loc in locs] or ["None."]) + [""]
    commenters = report.get("commenters") or {}
    out += _tag_md("Top commenters", commenters)
    tagged = report.get("tagged_users") or []
    if tagged:
        out += ["## Tagged users", ""] + \
            [f"- @{_md_clean(u)}" for u in tagged] + [""]
    out += _posts_md(report)
    out += _social_md(report)
    stories = report.get("stories") or {}
    if stories and stories.get("count"):
        out += ["## Stories", ""]
        for s in stories.get("items") or []:
            taken = _dt(s.get("taken_at"))
            expiry = _dt(s.get("expiring_at"))
            line = f"- story {_md_clean(s.get('id'))}"
            if taken:
                line += f" — posted {taken}"
            if expiry:
                line += f", expires {expiry}"
            if s.get("file"):
                line += f" (`{_md_clean(s['file'])}`)"
            out.append(line)
        out.append("")
    media = report.get("media_downloaded") or []
    if media:
        out += ["## Media downloaded", ""] + [f"- `{_md_clean(m)}`" for m in media] + [""]
    notes = report.get("notes") or []
    if notes:
        out += ["## Notes", ""] + [f"- {_md_cell(n)}" for n in notes] + [""]
    out += ["---", "", "*Public data only. Use responsibly.*", ""]
    return "\n".join(out)


def write_markdown(report: dict, out_dir: Path) -> Path:
    """Write report.md next to report.json."""
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "report.md"
    path.write_text(render_markdown(report), encoding="utf-8")
    return path


def print_summary(report: dict) -> None:
    p = report.get("profile") or {}
    counts = p.get("counts") or {}
    say("\n" + "=" * 60, "cyan")
    say_parts("  ", ("REPORT", "bold"), f": {report['target']}  ({report['profile_status']})")
    say("=" * 60, "cyan")
    if report["profile_status"] == "ok":
        say(f"  name        : {p.get('full_name')}")
        say(
            f"  followers   : {counts.get('followers')}  |  "
            f"following: {counts.get('following')}  |  posts: {counts.get('posts')}"
        )
        say(f"  private     : {p.get('is_private')}  |  verified: {p.get('is_verified')}")
        biz = p.get("is_business")
        exposed = p.get("business_contact_exposed")
        if biz is None and not p.get("business_category") and exposed is None:
            say(f"  business    : {_tri(biz)}")
        else:
            parts = [f"business: {_tri(biz)}"]
            if p.get("business_category"):
                parts.append(f"category: {p['business_category']}")
            if exposed is not None:
                parts.append(f"contact: {'yes' if exposed else 'no'}{_contact_channels(p)}")
            say("  business    : " + "  |  ".join(parts))
        biography = p.get("biography")
        if biography:
            say(f"  bio         : {biography[:90]}")
        hl = p.get("highlights") or []
        if hl:
            titles = ", ".join(h["title"][:22] for h in hl[:4])
            say(f"  highlights  : {len(hl)} ({titles}{'...' if len(hl) > 4 else ''})")
        if p.get("last_reel_at"):
            say(f"  last reel   : {str(p['last_reel_at'])[:19].replace('T', ' ')} UTC")
        badges = p.get("account_badges") or []
        if badges:
            say(f"  badges      : {', '.join(badges)}")
        if p.get("related_profiles"):
            say(f"  similar     : {', '.join(p['related_profiles'][:6])}")
    say(f"  posts       : {report['posts_count']} (deep-visited)")
    say(f"  hashtags    : {len(report['hashtags'])} unique")
    say(f"  mentions    : {len(report['mentions'])} unique")
    say(f"  locations   : {len(report['locations'])}")
    say(f"  emails      : {report['contacts']['emails'] or 'none'}")
    say(f"  phones      : {report['contacts']['phones'] or 'none'}")
    f = report["followers"]
    say(f"  followers   : count={f['count']}, collected={f['collected']}"
        + _wall_label(report, f))
    g = report["following"]
    say(f"  following   : count={g['count']}, collected={g['collected']}"
        + _wall_label(report, g))
    say(f"  media saved : {len(report['media_downloaded'])} files")
    stories = report.get("stories") or {}
    if stories and stories.get("count"):
        say(f"  stories     : {stories['count']} available (24h window)")
    for note in report.get("notes", []):
        say(f"  note        : {note}", "yellow")
    say("=" * 60, "cyan")

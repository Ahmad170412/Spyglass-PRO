"""Report writing for every platform, from the normalized result.

One report format regardless of which platform produced it: an operator
comparing an Instagram and an X profile should not have to learn two
layouts. Walled sections are printed as walled, with the reason — the
same honesty rule InstaCloak applies to follower lists.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from .schema import PROFILE_FIELDS, format_value, visible_fields


def render(result: dict) -> str:
    """Markdown report for one normalized result."""
    platform = result.get("platform", "?")
    handle = result.get("handle", "?")
    lines = [
        f"# {platform.title()} Recon — @{handle}",
        "",
        f"- **Profile:** {result.get('url') or 'n/a'}",
        f"- **Source:** {result.get('source') or 'n/a'}",
        f"- **Session:** {'burner logged in' if result.get('logged_in') else 'logged out'}",
        f"- **Collected:** {datetime.now().isoformat(timespec='seconds')}",
    ]
    if result.get("elapsed") is not None:
        lines.append(f"- **Elapsed:** {result['elapsed']}s")
    lines.append("")

    if result.get("error"):
        lines += [f"> **Collection error:** {result['error']}", ""]

    lines += ["## Profile", ""]
    fields = visible_fields(result)
    if fields:
        lines += ["| Field | Value |", "| --- | --- |"]
        for field in fields:
            label = field["label"]
            value = format_value(field, result.get(field["key"]))
            if field["type"] in ("link", "image"):
                value = f"<{value}>" if value.startswith("http") else value
            lines.append(f"| {label} | {value} |")
    else:
        lines.append("No profile fields retrieved.")
    lines.append("")

    posts = result.get("posts") or []
    if posts:
        lines += ["## Posts", "", f"{len(posts)} retrieved.", ""]
        for post in posts[:12]:
            bits = [post.get("caption") or ""]
            if post.get("likes") is not None:
                bits.append(f"{post['likes']} likes")
            if post.get("comments") is not None:
                bits.append(f"{post['comments']} comments")
            excerpt = " — ".join(b for b in bits if b)[:160]
            link = post.get("url") or ""
            lines.append(f"- {'[' + excerpt + '](' + link + ')' if link else excerpt}")
        lines.append("")

    if result.get("metrics"):
        lines += ["## Retrieved counts", ""]
        for name, value in sorted(result["metrics"].items()):
            lines.append(f"- {name.replace('_', ' ')}: {value:,}"
                         if isinstance(value, int) else f"- {name.replace('_', ' ')}: {value}")
        lines.append("")

    walls = result.get("walls") or {}
    if walls:
        lines += ["## Not retrieved", ""]
        for kind, info in walls.items():
            lines.append(f"- **{info.get('label', kind)}** — {info.get('why', 'unavailable')}")
        lines.append("")

    if result.get("media_files"):
        lines += ["## Media", ""]
        lines += [f"- `{path}`" for path in result["media_files"][:20]]
        lines.append("")

    if result.get("contacts"):
        lines += ["## Contacts", "", "```", str(result["contacts"])[:800], "```", ""]

    notes = result.get("notes") or []
    if notes:
        lines += ["## Notes", ""]
        lines += [f"- {note}" for note in notes]
        lines.append("")

    return "\n".join(lines) + "\n"


def write(result: dict, output_dir: str, filename: str) -> str:
    """Write the report under output_dir/filename and return its path."""
    directory = Path(output_dir)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / filename
    path.write_text(render(result), encoding="utf-8")
    return str(path)


def summary(result: dict) -> str:
    """One-line overview for the dashboard header."""
    platform = (result.get("platform") or "social").capitalize()
    handle = result.get("handle") or ""
    base = f"{platform} scan of @{handle}"
    if result.get("error"):
        return f"{base} — error"
    if not result.get("found"):
        return f"{base} — nothing retrieved"

    # Counts first: a display name that merely repeats the handle tells the
    # operator nothing about how much came back.
    bits = []
    for key, label in (("follower_count", "followers"),
                       ("following_count", "following"),
                       ("post_count", "posts")):
        value = result.get(key)
        if isinstance(value, int):
            bits.append(f"{value:,} {label}")
    name = result.get("display_name")
    if name and name.strip().lower() != handle.strip().lower():
        bits.append(str(name))
    detail = ", ".join(bits)
    return f"{base} — {detail}" if detail else f"{base} complete"


__all__ = ["render", "write", "summary", "PROFILE_FIELDS"]

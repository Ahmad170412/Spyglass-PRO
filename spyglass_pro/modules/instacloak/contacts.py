"""Email/phone/hashtag/mention scanning of bios and captions (pure functions)."""

from __future__ import annotations

import re

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
PHONE_RE = re.compile(
    r"(?<!\d)(?:\+?\d{1,3}[ .\-]?)?(?:\(\d{2,4}\)[ .\-]?)?\d{3,4}[ .\-]\d{3,4}"
    r"(?:[ .\-]\d{2,4})?(?!\d)")
HASHTAG_RE = re.compile(r"#([A-Za-z0-9_]+)")
MENTION_RE = re.compile(r"@([A-Za-z0-9_.]+)")


def collect_contacts(profile: dict, posts: list[dict]) -> dict:
    emails: list[str] = []
    phones: list[str] = []
    sources: list[str] = []

    def add_email(e: str, src: str) -> None:
        e = e.strip().rstrip(".,;")
        if e and e not in emails:
            emails.append(e)
            sources.append(src)

    def add_phone(p: str, src: str) -> None:
        p = p.strip().rstrip(".,;)")
        if p and p not in phones:
            phones.append(p)
            sources.append(src)

    be = profile.get("business_email")
    if be:
        add_email(be, "business_email")
    bp = profile.get("business_phone_number")
    if bp:
        add_phone(bp, "business_phone_number")

    bio = profile.get("biography") or ""
    for e in EMAIL_RE.findall(bio):
        add_email(e, "bio")
    for p in PHONE_RE.findall(bio):
        if sum(ch.isdigit() for ch in p) >= 7:
            add_phone(p, "bio")

    for post in posts:
        cap = post.get("caption") or ""
        for e in EMAIL_RE.findall(cap):
            add_email(e, "caption")
        for p in PHONE_RE.findall(cap):
            if sum(ch.isdigit() for ch in p) >= 9:
                add_phone(p, "caption")

    return {"emails": emails, "phones": phones, "sources": sources}


def count_matches(texts: list[str], pattern: re.Pattern) -> dict:
    out: dict[str, int] = {}
    for t in texts:
        for m in pattern.findall(t or ""):
            key = m.lower()
            out[key] = out.get(key, 0) + 1
    return out

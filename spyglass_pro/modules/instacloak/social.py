"""Social graph: followers/following modal scraping, login-wall honest.

Logged-out Instagram login-walls the follower modal and renders a
'suggested accounts' pool instead of the real list. The trap: that pool is
full of real-looking usernames — scraping it and reporting them as followers
would fabricate the social graph. So we (a) scope collection to the dialog,
(b) positively verify a genuine list is showing (Followers/Following header,
no login CTA), and (c) discard everything and report `login-walled` otherwise.
"""

from __future__ import annotations

import random
import re
import time

from .human import dismiss_login_popup, human_delay, human_move, human_scroll
from .ui import say

STRONG_WALL_RE = re.compile(
    r"(?i)(log in to (see|view|continue|follow|check)|login to see|you must log in|"
    r"sign up to see|log in to see who|to view this user's content|create an account to see)")


def detect_login_wall(text: str) -> bool:
    """True if page text looks like Instagram's logged-out login wall.

    Deliberately strict: the site header always shows bare "Log in"/"Sign up"
    links on every logged-out page, so we only match actual wall copy.
    """
    return bool(text and STRONG_WALL_RE.search(text))


SYSTEM_PATHS = {
    "accounts", "explore", "reel", "p", "stories", "direct", "notifications",
    "suggested", "tags", "locations", "web", "graphql", "api", "help", "about",
    "developers", "press", "jobs", "legal", "privacy", "terms", "meta",
}


def _list_looks_real(state: dict) -> bool:
    """Positive check that a dialog is the genuine follower list, not the login wall.

    The login wall renders a dialog (or interstitial) full of 'suggested
    accounts' with Follow buttons and login/signup CTAs; the real list has a
    'Followers'/'Following' header. Logged-out, a genuine list is rare --
    require the header or we treat it as walled.
    """
    if not state or not state.get("hasDialog"):
        return False
    if state.get("loginCta"):
        return False
    return bool(state.get("listHeader"))


def attempt_relationship_list(page, cfg: dict, username: str, kind: str) -> tuple[list, bool]:
    """Try to collect usernames from the followers/following modal.

    Returns (usernames, walled). Logged-out, Instagram login-walls this modal
    and shows a 'suggested accounts' pool instead of the real list -- we detect
    that (and verify the dialog really is a list) so suggestion accounts are
    never reported as followers. Counts are still reported regardless.
    """
    if kind not in ("followers", "following"):
        return [], True
    cap = cfg["max_followers"] if kind == "followers" else cfg["max_following"]
    say(f"  opening {kind} list...")
    try:
        page.goto(f"https://www.instagram.com/{username}/{kind}/",
                  wait_until="domcontentloaded", timeout=45000)
    except Exception:
        return [], True
    human_delay(cfg, 1.5, 3.0)
    dismiss_login_popup(page)

    usernames: set[str] = set()
    walled = False
    empty_scrolls = 0
    deadline = time.time() + 50

    for _ in range(60):
        if time.time() > deadline:
            break
        try:
            body_text = page.evaluate("() => document.body ? document.body.innerText : ''")
            if detect_login_wall(body_text or ""):
                walled = True
                break
        except Exception:
            pass

        try:
            found = page.evaluate(
                """() => {
                    const d = document.querySelector('[role="dialog"]');
                    if (!d) return [];
                    const seen = new Set();
                    d.querySelectorAll('a[href]').forEach(a => {
                        const h = a.getAttribute('href') || '';
                        const m = h.match(/^\\/([^\\/?#]+)\\/?$/);
                        if (m) seen.add(m[1]);
                    });
                    return Array.from(seen);
                }"""
            )
        except Exception:
            found = []

        before = len(usernames)
        for u in found or []:
            if u.lower() == username.lower() or u.lower() in SYSTEM_PATHS:
                continue
            usernames.add(u.lower())
        if len(usernames) == before:
            empty_scrolls += 1
            if empty_scrolls >= 4:
                break
        else:
            empty_scrolls = 0

        if len(usernames) >= cap:
            break

        # scroll the dialog (or the page if the dialog never rendered)
        try:
            dims = page.evaluate(
                """() => {
                    const d = document.querySelector('[role="dialog"]');
                    if (d) { const r = d.getBoundingClientRect();
                    return {x: Math.round(r.left + r.width/2), y: Math.round(r.top + r.height/2), inDialog: true}; }
                    return {x: Math.round(innerWidth/2), y: Math.round(innerHeight/2), inDialog: false};
                }"""
            )
            human_move(page, dims["x"], dims["y"])
        except Exception:
            pass
        human_scroll(page, random.randint(500, 900), 0.4, 1.0)

    # Verify the dialog is a genuine list -- not the login wall's suggestion pool
    if not walled:
        try:
            state = page.evaluate(
                """() => {
                    const d = document.querySelector('[role="dialog"]');
                    const out = {hasDialog: !!d, loginCta: false, listHeader: false};
                    if (!d) return out;
                    d.querySelectorAll('a[href]').forEach(a => {
                        const h = (a.getAttribute('href') || '').toLowerCase();
                        if (h.includes('/accounts/login') || h.includes('/accounts/signup')) {
                            out.loginCta = true;
                        }
                    });
                    const t = (d.innerText || '').toLowerCase();
                    out.listHeader = /(^|\n)(followers|following)($|\n)/.test(t);
                    return out;
                }"""
            )
        except Exception:
            state = {}
        if not _list_looks_real(state):
            # The wall's suggested accounts are NOT follower data -- discard them
            walled = True
            usernames.clear()

    # Zero rows collected + login UI present => login-walled, not an empty list
    if not walled and not usernames:
        try:
            low = (page.evaluate("() => document.body ? document.body.innerText : ''") or "").lower()
            if "log in" in low and "sign up" in low:
                walled = True
        except Exception:
            pass

    return sorted(usernames), walled

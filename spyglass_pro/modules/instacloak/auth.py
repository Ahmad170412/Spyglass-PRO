"""Burner-account login: state probing, the login flow, challenge handling.

The burner session is optional (menu 2 / config `[login]` / env vars). It
unlocks full follower/following lists and stories. Every failure degrades to
logged-out instead of crashing the run.
"""

from __future__ import annotations

import random
import re
import time

from .human import human_delay
from .ui import say

LOGIN_URL = "https://www.instagram.com/accounts/login/"
HOME_URL = "https://www.instagram.com/"

# Instagram rotates its login DOM; try these in order of specificity.
USERNAME_SELECTORS = (
    'input[name="username"]',
    'input[aria-label*="username" i]',
    'input[aria-label*="phone" i]',
    'input[placeholder*="username" i]',
    'input[placeholder*="phone" i]',
    'input[placeholder*="email" i]',
    'input[type="text"]',
)
PASSWORD_SELECTORS = ('input[name="password"]', 'input[type="password"]')

CHALLENGE_RE = re.compile(
    r"(?i)(confirmation code|enter the code|challenge required|we need to make sure "
    r"it's you|suspicious activity|we\'ve sent a code|add another device|verify it's you)")


def _login_state(page) -> dict:
    """DOM probe of the current auth state."""
    try:
        return page.evaluate("""() => {
            const visible = (el) => !!el && el.offsetParent !== null;
            const loginCtas = [...document.querySelectorAll(
                'a[href*="/accounts/login"], a[href*="/accounts/signup"]')]
                .filter(visible).length;
            const home = !!document.querySelector('svg[aria-label="Home"]');
            const avatar = !!document.querySelector('nav svg[aria-label="Profile"], ' +
                'nav img[alt], [aria-label="Profile"]');
            const inbox = !!document.querySelector('a[href*="/direct/inbox"]');
            return {loginCtas, home, avatar, inbox};
        }""")
    except Exception:
        return {}


def login_needed(state: dict) -> bool:
    """Pure decision: does this session still need the login flow?"""
    if not state:
        return True  # couldn't probe -> attempt login (harmless if already in)
    return bool(state.get("loginCtas")) or not (state.get("home")
                                                or state.get("avatar")
                                                or state.get("inbox"))


def _click_not_now(page) -> None:
    """Dismiss 'Save your login info?' / 'Save your password?' prompts."""
    try:
        for _ in range(3):
            clicked = page.evaluate("""() => {
                const btns = [...document.querySelectorAll('button, div[role="button"]')];
                const b = btns.find(el => (el.innerText || '').trim().toLowerCase() === 'not now');
                if (b) { b.click(); return true; }
                return false;
            }""")
            if not clicked:
                break
            page.wait_for_timeout(1200)
    except Exception:
        pass


def _wait_first(page, selectors: tuple, timeout: int) -> str | None:
    """Wait up to *timeout* for the first visible field matching any selector."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        for sel in selectors:
            try:
                if page.is_visible(sel, timeout=500):
                    return sel
            except Exception:
                pass
        page.wait_for_timeout(600)
    return None


def _login_page_snapshot(page) -> dict:
    """Describe what the login page is actually showing (for diagnostics)."""
    try:
        return page.evaluate("""() => {
            const vis = (el) => !!el && el.offsetParent !== null;
            const inputs = [...document.querySelectorAll('input')].filter(vis)
                .slice(0, 6).map(i => ({name: i.name || '', type: i.type || '',
                    aria: i.getAttribute('aria-label') || '',
                    ph: i.placeholder || ''}));
            const ctas = [...document.querySelectorAll('button, a')].filter(vis)
                .map(e => (e.innerText || '').trim())
                .filter(t => t && t.length < 40).slice(0, 8);
            const body = (document.body ? document.body.innerText : '')
                .replace(/\n+/g, ' | ').slice(0, 350);
            return {url: location.href, title: document.title, inputs, ctas, body};
        }""")
    except Exception:
        return {}


def _print_snapshot(snap: dict) -> None:
    """Print a compact, sanitized picture of the login page."""
    say(f"  page URL : {snap.get('url') or '?'}", "yellow")
    say(f"  title    : {(snap.get('title') or '?')[:90]}", "yellow")
    inputs = snap.get("inputs") or []
    if inputs:
        for i in inputs:
            say(f"  input    : name={i.get('name') or '-'} type={i.get('type') or '-'} "
                f"aria={i.get('aria') or '-'} placeholder={i.get('ph') or '-'}", "yellow")
    else:
        say("  input    : (none visible)", "yellow")
    ctas = snap.get("ctas") or []
    if ctas:
        say(f"  buttons  : {', '.join(str(c) for c in ctas[:6])}", "yellow")
    body = snap.get("body") or ""
    if body:
        say(f"  page text: {body[:220]}", "yellow")


def ensure_login(page, cfg: dict, username: str) -> bool:
    """Make sure the burner session is logged in. Returns True if logged in."""
    user, pw = cfg.get("login_username", ""), cfg.get("login_password", "")
    if not (cfg.get("login_enabled") and user and pw):
        return False

    # 1) already logged in? (persistent session from a previous run)
    try:
        page.goto(HOME_URL, wait_until="domcontentloaded", timeout=60000)
        page.wait_for_timeout(3000)
    except Exception:
        pass
    if not login_needed(_login_state(page)):
        say(f"  already logged in as @{user}", "green")
        return True

    # 2) perform the login
    say(f"  logging in as @{user} ...", "magenta")
    try:
        page.goto(LOGIN_URL, wait_until="domcontentloaded", timeout=60000)
        human_delay(cfg, 1.5, 3.0)
    except Exception:
        pass

    user_sel = _wait_first(page, USERNAME_SELECTORS, 15000)
    if not user_sel:
        # page may bounce/redirect on first load -- retry once, then report
        try:
            page.goto(LOGIN_URL, wait_until="domcontentloaded", timeout=60000)
            page.wait_for_timeout(2500)
        except Exception:
            pass
        user_sel = _wait_first(page, USERNAME_SELECTORS, 20000)
    if not user_sel:
        say("  couldn't find the username field on the login page.", "yellow")
        _print_snapshot(_login_page_snapshot(page))
        return False

    pw_sel = _wait_first(page, PASSWORD_SELECTORS, 8000)
    if not pw_sel:
        say("  found the username field but no password field.", "yellow")
        _print_snapshot(_login_page_snapshot(page))
        return False

    try:
        page.type(user_sel, user, delay=random.uniform(35, 80))
        human_delay(cfg, 0.4, 0.9)
        page.type(pw_sel, pw, delay=random.uniform(35, 80))
        human_delay(cfg, 0.4, 0.9)
        # submit: prefer the submit button, fall back to Enter (robust across
        # layout rotations, incl. the two-step 'password only' variant)
        try:
            page.click('button[type="submit"]', timeout=3000)
        except Exception:
            page.keyboard.press("Enter")
    except Exception as exc:
        say(f"  login form interaction failed: {exc}", "yellow")
        _print_snapshot(_login_page_snapshot(page))
        return False

    # 3) wait for completion (feed, challenge, or failure)
    deadline = time.time() + 45
    challenge = False
    while time.time() < deadline:
        page.wait_for_timeout(2500)
        try:
            body = (page.evaluate("() => document.body ? document.body.innerText : ''") or "")
        except Exception:
            body = ""
        if not login_needed(_login_state(page)):
            _click_not_now(page)
            say(f"  logged in as @{user}", "green")
            return True
        if CHALLENGE_RE.search(body):
            challenge = True
            break
    if challenge:
        say("  Instagram is challenging this login (verification code / suspicious activity).", "yellow")
        say("  Complete it in the browser window -- you have 120 seconds.", "yellow")
        deadline = time.time() + 120
        while time.time() < deadline:
            page.wait_for_timeout(3000)
            if not login_needed(_login_state(page)):
                _click_not_now(page)
                say(f"  logged in as @{user}", "green")
                return True
        say("  challenge not completed in time; continuing logged-out.", "yellow")
        return False
    say("  login did not complete; continuing logged-out.", "yellow")
    return False

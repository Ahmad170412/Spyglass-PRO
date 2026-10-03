"""Humanized interaction helpers: jittered delays, mouse, scroll, popups.

Every call here is best-effort and never raises — a failed cosmetic action
(e.g. the popup already closed) must not crash a run. The timing comes from
`random.uniform`, never fixed intervals, so no two runs behave alike.
"""

from __future__ import annotations

import random
import time


def human_delay(cfg: dict | None = None, lo: float | None = None,
                hi: float | None = None) -> None:
    lo = cfg["min_delay"] if (lo is None and cfg) else (1.2 if lo is None else lo)
    hi = cfg["max_delay"] if (hi is None and cfg) else (3.5 if hi is None else hi)
    time.sleep(random.uniform(max(lo, 0.1), max(hi, lo + 0.1)))


def human_move(page, x: int | None = None, y: int | None = None) -> None:
    """Move the mouse to (x, y) via a couple of intermediate points."""
    try:
        if x is None or y is None:
            dims = page.evaluate("() => ({w: innerWidth, h: innerHeight})")
            x = random.randint(60, max(61, dims["w"] - 60))
            y = random.randint(60, max(61, dims["h"] - 60))
        page.mouse.move(random.randint(max(0, x - 40), x + 40),
                        random.randint(max(0, y - 40), y + 40), steps=random.randint(3, 8))
        time.sleep(random.uniform(0.05, 0.2))
        page.mouse.move(x, y, steps=random.randint(2, 5))
    except Exception:
        pass


def human_scroll(page, delta: int, pause_lo: float = 0.35, pause_hi: float = 1.1) -> None:
    try:
        page.mouse.wheel(0, delta)
        time.sleep(random.uniform(pause_lo, pause_hi))
    except Exception:
        pass


def warmup_scrolls(page, n: int = 3) -> None:
    """Light footprint warm-up: a few organic scrolls up/down the page."""
    for _ in range(n):
        delta = random.choice([-1, 1]) * random.randint(350, 900)
        human_scroll(page, delta)
        human_delay(None, 0.8, 1.8)


def dismiss_login_popup(page) -> None:
    """Dismiss Instagram's login/signup nudge popup if present.

    The popup appears after a few seconds of browsing. We try clicking the
    close button first, then fall back to pressing Escape. Both are human-like.
    """
    try:
        # Wait a beat for the popup to potentially appear
        time.sleep(random.uniform(1.5, 3.0))

        # Try clicking the X close button (aria-label="Close" or role=dialog button)
        dismissed = page.evaluate("""() => {
            // Strategy 1: aria-label close button inside dialog
            const btn = document.querySelector('[role="dialog"] button[aria-label="Close"]')
                     || document.querySelector('[role="dialog"] svg[aria-label="Close"]')
                     || document.querySelector('div[role="dialog"] button:first-child');
            if (btn) { btn.click(); return true; }

            // Strategy 2: any button with an X-like SVG in the top-right of a dialog
            const dialog = document.querySelector('[role="dialog"]');
            if (dialog) {
                const buttons = dialog.querySelectorAll('button');
                for (const b of buttons) {
                    const rect = b.getBoundingClientRect();
                    // Close button is usually small and in the top-right corner
                    if (rect.width < 50 && rect.height < 50 && rect.right > 300) {
                        b.click();
                        return true;
                    }
                }
            }
            return false;
        }""")

        if not dismissed:
            # Fallback: press Escape (natural human response to popups)
            page.keyboard.press("Escape")
        else:
            # Small human pause after clicking
            time.sleep(random.uniform(0.3, 0.7))
    except Exception:
        pass

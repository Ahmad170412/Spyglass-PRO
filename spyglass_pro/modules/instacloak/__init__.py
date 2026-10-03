"""InstaCloak — stealth Instagram OSINT through a humanized, visible browser.

Package layout (keep each module single-purpose):

    cli        entry point, menu, per-command runners (main())
    config     config.toml + env loading; burner-login config writer
    engine     the OSINT run orchestration (collect)
    session    CloakBrowser launch with stealth options
    auth       burner login state machine + challenge handling
    human      humanized timing / mouse / scroll / popup dismissal
    jsonutil   low-level digging into Instagram's embedded JSON
    fetch      in-page fetch + media downloads (all traffic via the browser)
    profile    profile-node extraction + normalization (modern + legacy)
    post       post-node extraction + normalization + post-page visits
    stories    logged-in story tray scrape
    social     follower/following modal (login-wall detection)
    contacts   email/phone/hashtag/mention scanning
    report     report assembly + summary printing
    ui         ANSI colors, banner, shared printing helpers

Run from the repo root:  python3 main.py  (thin wrapper) or  python3 -m instacloak
"""

__version__ = "1.0.0"  # keep in sync with pyproject.toml

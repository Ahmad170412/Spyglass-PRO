"""Entry point: argument parsing, the interactive menu, and the command runners.

`python3 -m instacloak` and the root `main.py` wrapper both land here. The
menu offers OSINT / Login (burner) / Footprint / Exit; passing `-u` skips the
menu and runs OSINT directly (flag overrides merge into the loaded config).
"""

from __future__ import annotations

import argparse
import getpass
import sys

from . import __version__
from .auth import ensure_login
from .config import load_config, save_login_config
from .engine import collect, output_dir
from .report import print_summary, write_markdown
from .session import open_session
from .ui import NOTES, NOTES_LOGGED_IN, c, say, say_banner, say_parts

MENU_ITEMS = [("1", "OSINT"), ("2", "Login (burner)"),
              ("3", "Footprint"), ("4", "Exit")]


def cli_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="InstaCloak - stealth Instagram OSINT via a humanized browser",
    )
    p.add_argument("-u", "--username", help="target Instagram username (skips prompt)")
    p.add_argument("-y", "--yes", action="store_true", help="skip y/N confirmation")
    p.add_argument("--config", default=None, help="path to config.toml")
    p.add_argument("--headless", action="store_true", help="run without a visible window")
    p.add_argument("--max-posts", type=int, default=None, help="override max posts to visit")
    p.add_argument("--no-media", action="store_true", help="don't download media")
    p.add_argument("--no-followers", action="store_true", help="skip follower/following attempt")
    p.add_argument("--deep", action="store_true",
                   help="extra logged-out data: HD profile pic + highlight story covers")
    p.add_argument("--mode", choices=("login", "logout"), default=None,
                   help="session mode for this run: 'login' uses the burner, "
                        "'logout' forces logged-out (default: config)")
    p.add_argument("--version", action="version", version=f"InstaCloak {__version__}")
    return p.parse_args()


def show_menu() -> str:
    """Display the main menu and return the user's choice."""
    say_banner()
    say(f"\n  InstaCloak v{__version__}", "gold")
    for num, label in MENU_ITEMS:
        say_parts("  ", (num, "yellow"), "  ", (label, "yellow"))

    try:
        choice = input(c("  > ", "bold")).strip()
    except (EOFError, KeyboardInterrupt):
        choice = "4"
    return choice


def login_creds_configured(cfg: dict) -> bool:
    """Burner credentials exist (username + password) in config/env."""
    return bool(cfg.get("login_username")) and bool(cfg.get("login_password"))


def parse_run_mode(ans: str) -> bool | None:
    """Map the mode answer to a login decision.

    False -> logged out, True -> logged in (burner); None -> unrecognized.
    Empty/Enter defaults to logged out (stealth-first).
    """
    a = ans.strip().lower()
    if a in ("", "1", "logout", "logged out", "logged-out", "logged_out"):
        return False
    if a in ("2", "login", "logged in", "logged-in", "burner"):
        return True
    return None


def ask_run_mode(cfg: dict) -> bool | None:
    """Ask logged-out vs logged-in (only called when creds are configured).

    Returns True (login) / False (logged out) / None (aborted at EOF).
    Unrecognized answers are retried once, then default to logged out.
    """
    say_parts("  Burner login available: @", (str(cfg.get("login_username")), "yellow"), "")
    for _ in range(2):
        say("    (1) logged out (default)    (2) logged in (burner)")
        try:
            ans = input(c("  mode [1/2]: ", "bold"))
        except (EOFError, KeyboardInterrupt):
            return None
        mode = parse_run_mode(ans)
        if mode is not None:
            return mode
        say("  (answer 1 or 2)", "yellow")
    say("  defaulting to logged out.", "yellow")
    return False


def run_osint(cfg: dict, args) -> None:
    """Run the OSINT collection flow: mode first, then target, then confirm."""
    # 1) session mode — asked before anything else, and only when burner creds
    #    exist AND we're interactive AND no explicit --mode was given.
    #    Scripted runs (-y) and --mode keep the config/flag as-is.
    effective_cfg = cfg
    if args.mode is None and not args.yes and login_creds_configured(cfg):
        use_login = ask_run_mode(cfg)
        if use_login is None:
            say("\n  aborted.", "yellow")
            return
        effective_cfg = dict(cfg)
        effective_cfg["login_enabled"] = use_login
        if use_login:
            say_parts("  mode: logged in as @",
                      (str(cfg.get("login_username")), "magenta"), "")
        else:
            say("  mode: logged out", "dim")
        say("")

    # 2) target
    username = args.username
    if not username:
        try:
            username = input(c("  target username: ", "bold")).strip().lstrip("@").lower()
        except EOFError:
            say("\n  no target given — aborting.", "yellow")
            return
        if not username:
            say("  no target.", "yellow")
            return

    say(f"\n  Target: @{username}\n", "bold")
    will_login = bool(effective_cfg.get("login_enabled")
                      and login_creds_configured(effective_cfg))
    say(NOTES_LOGGED_IN if will_login else NOTES)

    # 3) final confirmation
    if not args.yes:
        try:
            ok = input(c("\n  Proceed? [y/N] ", "bold")).strip().lower()
        except (EOFError, KeyboardInterrupt):
            say("\n  aborted.", "yellow")
            return
        if ok not in ("y", "yes"):
            say("  aborted.", "yellow")
            return

    try:
        report = collect(effective_cfg, username)
        print_summary(report)
        _offer_markdown_export(effective_cfg, report, args)
    except KeyboardInterrupt:
        say("\n  interrupted by user.", "yellow")
    except Exception as exc:
        say(f"\n  unexpected error: {exc.__class__.__name__}: {exc}", "red")
        say("  re-run with a residential proxy (config.toml) if this looks "
            "like an Instagram block, or check the traceback above.", "yellow")
        raise


def _offer_markdown_export(cfg: dict, report: dict, args) -> None:
    """Ask whether to also write report.md next to report.json.

    Interactive runs get a y/N prompt. Non-interactive runs with -y (cron/CI)
    auto-save so the markdown is always produced; a plain piped run without -y
    keeps the default (no).
    """
    if args.yes:
        save_md = True
    elif sys.stdin.isatty():
        try:
            ans = input(c("\n  Save markdown report (report.md)? [y/N] ", "bold")).strip().lower()
            save_md = ans in ("y", "yes")
        except (EOFError, KeyboardInterrupt):
            save_md = False
    else:
        save_md = False
    if save_md:
        try:
            md_path = write_markdown(report, output_dir(cfg, report["target"]))
            say_parts("  markdown: ", (str(md_path), "green"))
        except Exception as exc:
            say(f"  could not write markdown report: {exc}", "yellow")


def run_login(cfg: dict, args) -> None:
    """Configure the burner-account login (saved to config.toml)."""
    say("\n  Burner login — full follower/following lists + stories require a", "bold")
    say("  logged-in session. NEVER use your primary account.", "bold")
    say("  Credentials are saved to config.toml (chmod 600) or use the env vars\n")
    who = cfg.get("login_username") or "none"
    say(f"  current: {'enabled' if cfg.get('login_enabled') else 'disabled'} (@{who})\n")
    try:
        ok = input(c("  Configure burner login? [y/N] ", "bold")).strip().lower()
    except (EOFError, KeyboardInterrupt):
        say("  aborted.", "yellow")
        return
    if ok not in ("y", "yes"):
        say("  leaving login config unchanged.", "yellow")
        return
    user = input(c("  burner username: ", "bold")).strip()
    pw = getpass.getpass(c("  burner password: ", "bold")).strip()
    if not user or not pw:
        say("  empty values -- aborting.", "yellow")
        return
    path = save_login_config(args.config or "config.toml", user, pw, enabled=True)
    say_parts("  saved to ", (path, "green"))
    cfg["login_enabled"], cfg["login_username"], cfg["login_password"] = True, user, pw
    try:
        test = input(c("  Test the login now (opens a visible browser)? [y/N] ", "bold")).strip().lower()
    except (EOFError, KeyboardInterrupt):
        return
    if test in ("y", "yes"):
        ctx = open_session(cfg, "login_test")
        page = ctx.new_page()
        try:
            ok_login = ensure_login(page, cfg, "login_test")
            say("  login test: " + ("OK" if ok_login else "FAILED"),
                "green" if ok_login else "red")
        finally:
            try:
                ctx.close()
            except Exception:
                pass


def run_footprint() -> None:
    """Placeholder for footprint / auto-scroll mode (V1.1)."""
    say_parts("\n  Footprint mode — ", ("V1.1 feature, coming soon!", "gold", "bold"),
              "\n  Self-driven Reels-scroll auto-footprint is next on the roadmap.\n")


def main() -> None:
    args = cli_args()

    # Non-interactive stdin without a target: the menu can't read input, so a
    # piped/CI run would spin uselessly (or EOF-traceback mid-flow). Abort with
    # a usage hint instead of the banner/menu dance.
    if not args.username and not sys.stdin.isatty():
        say("\n  non-interactive input detected (no TTY). Pass a target as a flag:", "yellow")
        say("    python3 main.py -u <username> [--headless] [-y] [--deep]\n", "gold")
        return

    cfg = load_config(args.config)

    if args.headless:
        cfg["headless"] = True
    if args.max_posts is not None:
        cfg["max_posts"] = args.max_posts
    if args.no_media:
        cfg["download_media"] = False
    if args.no_followers:
        cfg["attempt_followers"] = False
    if args.deep:
        cfg["deep"] = True
    if args.mode == "login":
        if not (cfg.get("login_username") and cfg.get("login_password")):
            say("  --mode login given but no burner credentials configured "
                "(menu 2 / INSTACLOAK_LOGIN_* / config [login]).", "yellow")
        cfg["login_enabled"] = True
    elif args.mode == "logout":
        cfg["login_enabled"] = False

    # Direct mode: if -u is passed, skip menu and run OSINT directly
    if args.username:
        run_osint(cfg, args)
        return

    # Interactive menu loop
    try:
        while True:
            choice = show_menu()
            if choice == "1":
                run_osint(cfg, args)
            elif choice == "2":
                run_login(cfg, args)
            elif choice == "3":
                run_footprint()
            elif choice == "4":
                say("\n  goodbye.\n", "gold")
                break
            else:
                say("  invalid choice.", "yellow")
    except KeyboardInterrupt:
        say("\n\n  goodbye.\n", "gold")

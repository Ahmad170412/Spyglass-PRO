"""Terminal helpers: banner + printing, all rendered through one rich Console.

Single source of truth for color decisions (TTY detection, NO_COLOR, and the
INSTACLOAK_COLOR override). Every printed line goes through `c()`/`say()`,
which strip terminal control characters from the *text* first: profiles,
bios, and post captions are attacker-controlled (any public Instagram user),
and a crafted bio must not be able to inject escape sequences into the
operator's terminal.
"""

from __future__ import annotations

import os
import re
import sys

from rich.console import Console
from rich.text import Text

# ANSI SGR numbers kept for the inline `c()` helper; rich styles for whole lines.
ANSI = {"green": 32, "cyan": 36, "yellow": 33, "red": 31, "dim": 2, "bold": 1,
        "magenta": 95, "gold": 93}
_RICH_STYLE = {"green": "green", "cyan": "cyan", "yellow": "yellow",
               "red": "red", "dim": "dim", "bold": "bold",
               "magenta": "bright_magenta", "gold": "bright_yellow"}

# INSTACLOAK rendered with figlet's ANSI Shadow font (canonical, uniform
# spacing, trailing whitespace trimmed so no line can wrap at 80 columns).
BANNER = r"""██╗███╗   ██╗███████╗████████╗ █████╗  ██████╗██╗      ██████╗  █████╗ ██╗  ██╗
██║████╗  ██║██╔════╝╚══██╔══╝██╔══██╗██╔════╝██║     ██╔═══██╗██╔══██╗██║ ██╔╝
██║██╔██╗ ██║███████╗   ██║   ███████║██║     ██║     ██║   ██║███████║█████╔╝
██║██║╚██╗██║╚════██║   ██║   ██╔══██║██║     ██║     ██║   ██║██╔══██║██╔═██╗
██║██║ ╚████║███████║   ██║   ██║  ██║╚██████╗███████╗╚██████╔╝██║  ██║██║  ██╗
╚═╝╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝
        stealth instagram recon -- public data, human touch"""

NOTES = """\
Will collect (public data only, logged-out):
  - profile: bio, stats, verification, business category, contact info
  - recent posts: captions, hashtags, mentions, likes/comments, geotags
  - media: profile picture + post images (videos optional)
  - social graph: follower/following COUNTS always; usernames best-effort
    (Instagram login-walls these for logged-out visitors -- configure a
    burner login via the Login menu option to unlock them)
  - contact info: public email/phone (business profiles) + bio/caption scans

Cautions:
  - Private accounts return almost nothing. That's Instagram, not a bug.
  - Use a residential proxy (config.toml) for real-world stealth; datacenter
    IPs are blocked instantly by Instagram.
  - Keep volume low: single targets, spaced-out runs. This is recon, not a
    firehose.
  - Public data, but scraping technically violates Instagram's ToS. Your call.
"""

NOTES_LOGGED_IN = """\
Will collect (public data, using the logged-in burner session):
  - everything logged-out collects, PLUS:
  - follower/following username lists (best-effort; private targets stay
    hidden unless the burner follows them first)
  - stories in the 24h window (when the target has active ones)

Cautions:
  - The session makes you a real, logged-in account to Instagram -- keep
    volume low, and this is why you use a dedicated burner, never your
    primary account.
  - Private accounts still expose almost nothing unless you follow them.
  - Public data, but scraping technically violates Instagram's ToS. Your call.
"""

# C0 control chars + DEL (keep \n and \t). Strips ESC sequences, bells, etc.
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _make_console() -> Console:
    """One Console for everything; color decisions live here.

    Priority: INSTACLOAK_COLOR=1 forces color on, =0 or NO_COLOR forces it
    off; otherwise rich's own detection (real TTY) decides.
    """
    force = os.environ.get("INSTACLOAK_COLOR")
    if force == "1":
        color_system = "standard"
    elif force == "0" or os.environ.get("NO_COLOR") is not None:
        color_system = None
    else:
        color_system = None if not sys.stdout.isatty() else "standard"
    return Console(color_system=color_system, highlight=False, markup=False,
                   emoji=False)


console = _make_console()


def _styles(*names: str) -> str:
    return " ".join(_RICH_STYLE[s] for s in names if s in _RICH_STYLE)


def say(msg: str, *styles: str) -> None:
    """Print one whole line through rich (text is sanitized of control chars).

    Styling comes from rich itself; `msg` must not embed raw ANSI sequences
    (rich would strip their ESC byte and leave visible `[..m` residue). For
    colored substrings inside a line, use `say_parts` instead.
    """
    console.print(_CONTROL_RE.sub("", msg), style=_styles(*styles))


def say_parts(*parts) -> None:
    """Print one line composed of plain and styled segments, safely.

    Each part is either a plain string or a `(text, *styles)` tuple. Segments
    are rendered as rich Text spans - no raw ANSI and no markup parsing - so
    arbitrary (attacker-controlled) text stays inert and styled parts still
    get proper colors.
    """
    line = Text()
    for part in parts:
        if isinstance(part, tuple):
            text, *styles = part
            line.append(_CONTROL_RE.sub("", str(text)), style=_styles(*styles))
        else:
            line.append(_CONTROL_RE.sub("", str(part)))
    console.print(line)


def c(text: str, *styles: str) -> str:
    """Return `text` wrapped in raw ANSI - for `input()` prompts only.

    Python writes the prompt straight to the TTY, so raw codes render there.
    Never embed the result inside `say()`/`console.print` text: rich strips
    the ESC byte from string content. Use `say_parts` for colored substrings.
    """
    text = _CONTROL_RE.sub("", text)
    if console.color_system is None:
        return text
    codes = ";".join(str(ANSI[s]) for s in styles if s in ANSI)
    return f"\x1b[{codes}m{text}\x1b[0m" if codes else text


def section(n: int, total: int, msg: str) -> None:
    say(f"\n[{n}/{total}] {msg}", "cyan", "bold")


def say_banner() -> None:
    """Print the banner: purple ASCII letters, yellow tagline."""
    lines = BANNER.splitlines()
    for line in lines[:-1]:
        say(line, "magenta", "bold")
    say(lines[-1], "gold", "bold")

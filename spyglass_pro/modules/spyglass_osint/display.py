"""Terminal message helpers for the engine modules.

The interactive CLI — menus, prompts, and the per-module result
renderers — lived in upstream Spyglass-OSINT's ``__main__.py``.
The dashboard replaced that UI, so only the progress-message
helpers the engine modules import (``info`` / ``err``) remain.
"""

try:
    from rich.console import Console as _Console
    from rich.style import Style

    _con = _Console(highlight=False)
    _RICH = True

    def _style(*, fg=None, bold=False, dim=False):
        return Style(color=fg, bold=bold, dim=dim)
except ImportError:
    _RICH = False
    _con = None

    def _style(*, fg=None, bold=False, dim=False):
        class _Null:
            def __call__(self, s):
                return s
        return _Null()

_GREEN = "#00ff00"


def info(msg):
    _print(f"[*] {msg}", _GREEN)


def err(msg):
    _print(msg, "red")


def _print(text, color=None, bold=False, dim=False):
    if _RICH:
        # markup=False: engine output is plain text, so "[word]"
        # must not be interpreted as a Rich style tag.
        _con.print(text, style=_style(fg=color, bold=bold, dim=dim), markup=False)
    else:
        print(text)

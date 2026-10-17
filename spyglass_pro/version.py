"""Version metadata for the dashboard and the vendored engine.

The standalone Spyglass-OSINT CLI's ``--version`` flag is gone: the
dashboard replaced that UI, so this module is the single source of truth
for the version the API reports. It matches ``pyproject.toml`` exactly —
one version for the distribution and the app, so ``pip show`` and
``/api/status`` can never disagree.
"""

__version__ = "1.1.0"

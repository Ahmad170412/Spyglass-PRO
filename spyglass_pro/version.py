"""Version metadata for the dashboard and the vendored engine.

The standalone Spyglass-OSINT CLI's ``--version`` flag is gone: the
dashboard replaced that UI, so this module is the single source of truth
for the version the API reports. The distribution version in
``pyproject.toml`` stays PEP 440-valid on its own.
"""

__version__ = "1.0.0-pro"
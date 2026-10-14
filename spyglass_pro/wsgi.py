"""WSGI entry point — code-only prod serving, no container needed.

Any WSGI server can target this::

    gunicorn spyglass_pro.wsgi:app
    waitress-serve --host=127.0.0.1 --port=5000 spyglass_pro.wsgi:app
    python -m spyglass_pro  # uses waitress when available
"""

from .app import app

application = app

"""Console entry point for ``spyglass-pro`` (declared in pyproject.toml).

Flags override the matching environment variables; anything not
passed falls back to the env, then to safe defaults in ``app.run``.
"""

import argparse
import os

from .app import run


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="spyglass-pro",
        description="Spyglass-Pro — unified OSINT dashboard",
    )
    parser.add_argument("--host",
                        help="bind address (default 127.0.0.1; "
                             "env: SPYGLASS_PRO_HOST)")
    parser.add_argument("--port", type=int,
                        help="port (default 5000; env: SPYGLASS_PRO_PORT)")
    parser.add_argument("--token",
                        help="require this Bearer token on /api/* "
                             "(env: SPYGLASS_PRO_TOKEN)")
    parser.add_argument("--debug", action="store_true",
                        help="Werkzeug debug mode — RCE console; "
                             "never enable on a reachable host")
    parser.add_argument("--server", choices=["auto", "flask", "waitress"],
                        help="WSGI server (default auto: waitress unless --debug; "
                             "env: SPYGLASS_PRO_SERVER)")
    parser.add_argument("--threads", type=int,
                        help="waitress thread pool size (default 8; "
                             "env: SPYGLASS_PRO_THREADS)")
    args = parser.parse_args(argv)

    if args.host:
        os.environ["SPYGLASS_PRO_HOST"] = args.host
    if args.port:
        os.environ["SPYGLASS_PRO_PORT"] = str(args.port)
    if args.token:
        os.environ["SPYGLASS_PRO_TOKEN"] = args.token
    if args.debug:
        os.environ["SPYGLASS_PRO_DEBUG"] = "1"
    if args.server:
        os.environ["SPYGLASS_PRO_SERVER"] = args.server
    if args.threads:
        os.environ["SPYGLASS_PRO_THREADS"] = str(args.threads)

    run()


if __name__ == "__main__":
    main()

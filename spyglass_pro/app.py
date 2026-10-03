import os
import secrets
from urllib.parse import urlparse

from flask import Flask, jsonify, render_template, request

from spyglass_pro import __version__, runner

app = Flask(__name__, template_folder="templates", static_folder="static")
# Random per-process key unless explicitly configured. The dashboard
# uses no sessions today, but a known fallback key would allow session
# forgery the moment any route starts using Flask sessions.
app.config["SECRET_KEY"] = os.environ.get("SPYGLASS_PRO_SECRET") or secrets.token_hex(32)

# Proxy URLs accepted by /api/proxy. Anything else (file://, gopher://,
# junk with control characters, ...) is rejected before it reaches the
# process environment that every subprocess inherits.
_PROXY_SCHEMES = {"http", "https", "socks4", "socks4a", "socks5", "socks5h"}


def _validate_proxy(value):
    """Return the proxy URL if it is safe, else None."""
    value = (value or "").strip()
    if not value:
        return ""
    # Control chars / embedded whitespace would ride the env vars
    # into every subprocess (and could smuggle header breaks).
    if any(ord(ch) < 32 or ch.isspace() for ch in value):
        return None
    try:
        parsed = urlparse(value)
    except ValueError:
        return None
    if parsed.scheme.lower() not in _PROXY_SCHEMES or not parsed.hostname:
        return None
    return value


def _authorized():
    """True when no token gate is configured or the caller presented it."""
    token = os.environ.get("SPYGLASS_PRO_TOKEN")
    if not token:
        return True
    if not request.path.startswith("/api/"):
        return True  # the HTML shell is harmless; the API is gated
    auth = (request.headers.get("Authorization") or "").split(None, 1)
    supplied = auth[1].strip() if len(auth) == 2 else ""
    if not supplied:
        supplied = request.args.get("token") or request.headers.get("X-Spyglass-Token") or ""
    return secrets.compare_digest(supplied.encode(), token.encode())


@app.before_request
def _gate_api():
    if not _authorized():
        return jsonify({"error": "unauthorized: set SPYGLASS_PRO_TOKEN and send it as a Bearer token"}), 401


@app.route("/")
def index():
    # The version badge is rendered from version.py — one source of truth.
    return render_template("index.html", version=__version__)


@app.route("/api/status")
def api_status():
    modules = {
        "spyglass": {"available": True, "label": "Spyglass-OSINT", "icon": "radar"},
        "instacloak": {"available": True, "label": "InstaCloak", "icon": "camera"},
        "lens_extender": {"available": True, "label": "Lens-Extender", "icon": "lens"},
    }
    return jsonify({
        "status": "ok",
        "version": __version__,
        "proxy": os.environ.get("SPYGLASS_PROXY", ""),
        "modules": modules,
    })


@app.route("/api/proxy", methods=["GET", "POST"])
def api_proxy():
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        proxy = _validate_proxy(data.get("proxy", ""))
        if proxy is None:
            return jsonify({
                "error": "invalid proxy URL — allowed schemes: http, https, socks4, socks4a, socks5, socks5h"
            }), 400
        if proxy:
            os.environ["SPYGLASS_PROXY"] = proxy
            os.environ["ALL_PROXY"] = proxy
            os.environ["HTTP_PROXY"] = proxy
            os.environ["HTTPS_PROXY"] = proxy
        else:
            for key in ("SPYGLASS_PROXY", "ALL_PROXY", "HTTP_PROXY", "HTTPS_PROXY"):
                os.environ.pop(key, None)
        return jsonify({"proxy": proxy, "status": "updated"})
    return jsonify({"proxy": os.environ.get("SPYGLASS_PROXY", "")})


@app.route("/api/spyglass/run")
def api_spyglass_run():
    """Run one Spyglass-OSINT module (email/username/phone/website/
    darkweb/ip/opsec/metadata). Extra query params become module flags
    (json/csv/report/store, darkweb type hint, ip ports)."""
    module = request.args.get("module", "")
    if not module:
        return jsonify({"error": "module parameter required"})
    target = request.args.get("target", "")
    flags = {key: value for key, value in request.args.items()
             if key not in ("module", "target")}
    return jsonify(runner.run_job(runner.run_spyglass, module, target, flags))


@app.route("/api/instacloak/run", methods=["POST"])
def api_instacloak_run():
    """Run one InstaCloak profile collection."""
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    if not username:
        return jsonify({"error": "username required"})
    return jsonify(runner.run_job(runner.run_instacloak, username, data))


@app.route("/api/lens/run")
def api_lens_run():
    """Run Lens-Extender passive recon, optionally with an nmap scan."""
    target = request.args.get("target", "")
    if not target:
        return jsonify({"error": "target required"})
    flags = {key: value for key, value in request.args.items()
             if key != "target"}
    return jsonify(runner.run_job(runner.run_lens, target, flags))


@app.route("/api/investigate/run", methods=["POST"])
def api_investigate_run():
    """Correlated multi-input investigation."""
    data = request.get_json(silent=True) or {}
    return jsonify(runner.run_job(runner.run_investigate, data))


@app.route("/api/cases")
def api_cases():
    """Stored cases from both tools' case stores."""
    return jsonify(runner.list_cases())


@app.route("/api/cases/diff")
def api_cases_diff():
    """Entities added/removed between a target's two most recent runs."""
    return jsonify(runner.case_diff(request.args.get("target", ""),
                                    request.args.get("qtype")))


@app.route("/api/cases/timeline")
def api_cases_timeline():
    """Chronological entity snapshots for a stored target."""
    return jsonify(runner.case_timeline(request.args.get("target", ""),
                                        request.args.get("qtype")))


@app.route("/api/cases/profile")
def api_cases_profile():
    """Latest stored run per query type, merged into one dossier."""
    return jsonify(runner.case_profile(request.args.get("target", "")))


def bind_config():
    """(host, port, debug) from the environment, with safe defaults."""
    host = os.environ.get("SPYGLASS_PRO_HOST", "127.0.0.1")
    port = int(os.environ.get("SPYGLASS_PRO_PORT", "5000"))
    # Werkzeug debug mode ships an interactive traceback console that is
    # effectively arbitrary code execution. Off by default — opt in with
    # SPYGLASS_PRO_DEBUG=1 on a trusted, loopback-only deployment.
    debug = os.environ.get("SPYGLASS_PRO_DEBUG", "0") == "1"
    return host, port, debug


def run():
    host, port, debug = bind_config()
    if os.environ.get("SPYGLASS_PRO_TOKEN"):
        print("Spyglass-Pro: API token authentication enabled")
    elif host.lower() not in ("127.0.0.1", "localhost", "::1"):
        print("WARNING: binding to a non-loopback address without SPYGLASS_PRO_TOKEN — "
              "the dashboard and its scan engines are unauthenticated. "
              "Set SPYGLASS_PRO_TOKEN before exposing this server.")
    app.run(host=host, port=port, debug=debug)

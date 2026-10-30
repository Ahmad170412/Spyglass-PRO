import importlib
import json
import os
import secrets
import shutil
import threading
import time
from urllib.parse import urlparse, urlsplit

from flask import (Flask, Response, jsonify, render_template, request,
                   send_file, stream_with_context)

from spyglass_pro import __version__, runner, scope

app = Flask(__name__, template_folder="templates", static_folder="static")
# Random per-process key unless explicitly configured. The dashboard
# uses no sessions today, but a known fallback key would allow session
# forgery the moment any route starts using Flask sessions.
app.config["SECRET_KEY"] = os.environ.get("SPYGLASS_PRO_SECRET") or secrets.token_hex(32)
# Templates are cached in memory for the life of the process, so an edited
# index.html otherwise keeps serving the old markup until a restart. This
# only re-checks mtimes on request — it does not enable the debug console.
app.config["TEMPLATES_AUTO_RELOAD"] = True
app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0

# Proxy URLs accepted by /api/proxy. Anything else (file://, gopher://,
# junk with control characters, ...) is rejected before it reaches the
# process environment that every subprocess inherits.
_PROXY_SCHEMES = {"http", "https", "socks4", "socks4a", "socks5", "socks5h"}

# Optional CLI tools the engines shell out to. blackbird ships as a script,
# hence the two-name lookup. Keep in sync with spyglass_osint.utils.
#
# No scanners appear here: nmap, gobuster and httpx were removed from the
# engines, and nothing in this application opens a connection to a target.
# If you find yourself adding one back, it belongs in Spyglass-Crimson.
_TOOL_PROBES = {
    "holehe": ("holehe",),
    "user-scanner": ("user-scanner",),
    "sherlock": ("sherlock",),
    "maigret": ("maigret",),
    "blackbird": ("blackbird", "blackbird.py"),
    "ignorant": ("ignorant",),
    "phoneinfoga": ("phoneinfoga",),
    "dig": ("dig",),
    "whois": ("whois",),
    "exiftool": ("exiftool",),
}


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
    # urlparse does not validate the port: "host:abc" and "host:99999"
    # both parse and only blow up when ``.port`` is read — which the
    # masking path does on every /api/status. Reject a broken port here,
    # at the door, instead of storing a proxy that 500s the dashboard.
    try:
        port = parsed.port
    except ValueError:
        return None
    if port is not None and port < 1:
        return None
    return value


def _mask_proxy(value):
    """Proxy URL with any userinfo hidden, for anything that echoes it back.

    The credential in ``http://user:pass@host:port`` is the secret; the host
    and port are not. A proxy without credentials (``socks5://127.0.0.1:9050``)
    is returned unchanged because it holds no secret. ``/api/status`` and the
    Settings snapshot must never put a real credential on the wire — the
    dashboard only ever needs to show *that* a proxy is set.
    """
    value = (value or "").strip()
    if not value:
        return ""
    try:
        parsed = urlparse(value)
    except ValueError:
        return "••••"
    if parsed.username or parsed.password:
        host = parsed.hostname or ""
        try:
            port = parsed.port
        except ValueError:
            # A malformed port ("host:abc") parses but cannot be read.
            # Masking runs on /api/status and the Settings snapshot — it
            # must never be the thing that answers 500.
            port = None
        port_suffix = f":{port}" if port else ""
        return f"{parsed.scheme}://••••@{host}{port_suffix}"
    return value


def _job_response(result):
    """Serve a job result, mapping a queue rejection to HTTP 429.

    run_job marks refusals with runner.REJECTED_KEY. Returning them as 429 lets
    a client tell "server is busy, retry" apart from "the scan ran and failed",
    which a 200 carrying an "error" key does not convey.
    """
    if isinstance(result, dict) and result.pop(runner.REJECTED_KEY, False):
        return jsonify(result), 429
    return jsonify(result)


def _wants_async(data=None):
    """True when the caller asked for a non-blocking job.

    Opt-in via ``?async=1`` (or ``Prefer: respond-async``, or JSON
    ``{"async": 1}`` on POST) so every existing sync client keeps
    blocking behavior unchanged.
    """
    flag = (request.args.get("async") or "").strip().lower()
    if flag in ("1", "true", "yes"):
        return True
    if isinstance(data, dict):
        val = data.get("async")
        if val is True or (isinstance(val, (int, str)) and str(val).lower() in ("1", "true", "yes")):
            return True
    prefer = (request.headers.get("Prefer") or "").lower()
    return "respond-async" in prefer


def _submit_or_run(fn, *args, pool=None, _data=None):
    """Shared helper: 202 + job_id when async requested, else blocking."""
    if _wants_async(_data):
        result = runner.submit_job(fn, *args, pool=pool)
        if isinstance(result, dict) and result.pop(runner.REJECTED_KEY, False):
            return jsonify(result), 429
        return jsonify(result), 202
    if pool is not None and pool is not runner.JOB_POOL:
        # Sync social path runs in its isolated pool so a long browser
        # collection does not hold a generic scan worker. Same MAX_QUEUE
        # back-pressure as run_job, same flattened error cap.
        with runner._JOB_LOCK:
            if runner._PENDING >= runner.MAX_QUEUE:
                return jsonify({"error": f"{getattr(fn, '__name__', 'job')} rejected: "
                                         f"job queue full ({runner.MAX_QUEUE} pending)"}), 429
            runner._PENDING += 1
        holder = {}
        try:
            fut = pool.submit(fn, *args)
            holder["result"] = fut.result(timeout=runner.JOB_TIMEOUT)
        except Exception as exc:
            from concurrent.futures import TimeoutError as _TE
            if isinstance(exc, _TE):
                holder["result"] = {"error": f"{getattr(fn, '__name__', 'job')} timed out "
                                              f"after {int(runner.JOB_TIMEOUT)}s"}
            else:
                holder["result"] = {"error": f"{getattr(fn, '__name__', 'job')} failed: "
                                              f"{runner._safe_error(exc)}"}
        finally:
            with runner._JOB_LOCK:
                runner._PENDING -= 1
        return _job_response(holder["result"])
    return _job_response(runner.run_job(fn, *args))


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


# Names a browser may use to reach the dashboard when it runs without a
# token. DNS rebinding points an attacker's own domain at 127.0.0.1, so the
# rebound request carries that domain as ``Host`` and looks same-origin to
# the attacker's page — the one thing that stops it reading the API is
# refusing a Host that is not loopback. Operators who serve the dashboard
# under a real hostname add it to SPYGLASS_PRO_ALLOWED_HOSTS (comma-separated;
# "*" disables the check).
_LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1", "0.0.0.0", "::"}
_WILDCARD_BINDS = {"0.0.0.0", "::"}


def _host_name(host):
    """Lowercased hostname from a Host header, port and IPv6 brackets stripped."""
    try:
        return (urlsplit("//" + (host or "").strip()).hostname or "").lower()
    except ValueError:
        return ""


def _origin_host(origin):
    """Lowercased hostname from a full Origin URL, or '' when it has none."""
    try:
        return (urlsplit((origin or "").strip()).hostname or "").lower()
    except ValueError:
        return ""


def _allowed_hosts():
    """(allowed loopback/bind/allowlist names, wildcard) for this process."""
    names = set(_LOOPBACK_HOSTS)
    for part in (os.environ.get("SPYGLASS_PRO_ALLOWED_HOSTS") or "").split(","):
        part = part.strip().lower()
        if not part:
            continue
        if part == "*":
            return names, True
        names.add(_host_name(part) or part)
    try:
        host, _port, _debug = bind_config()
    except Exception:
        host = ""
    if host and host.lower() not in _WILDCARD_BINDS:
        names.add(host.lower())
    return names, False


def _host_allowed():
    """False when an unauthenticated request arrives under a foreign Host.

    Only enforced while the dashboard has no token: with one set, the token
    is the control (an attacker page cannot present it) and hostname- or
    proxy-based access must keep working. The default — no token, loopback
    bind — is exactly the rebinding case, and it is closed here.
    """
    if os.environ.get("SPYGLASS_PRO_TOKEN"):
        return True
    allowed, wildcard = _allowed_hosts()
    if wildcard:
        return True
    host = _host_name(request.host)
    return not host or host in allowed


@app.before_request
def _gate_request():
    # CSRF: browsers label cross-site requests and send Origin on any
    # cross-origin one, so a foreign page cannot drive the API (including the
    # side-effecting GET run endpoints) even though it can emit the request.
    # A non-browser client (curl, the CLI) sends neither header and is
    # unaffected.
    if (request.headers.get("Sec-Fetch-Site") or "").strip().lower() == "cross-site":
        return jsonify({"error": "cross-site request refused"}), 403
    origin = request.headers.get("Origin")
    if origin is not None:
        stripped = origin.strip().lower()
        if stripped == "null" or _origin_host(origin) != _host_name(request.host):
            return jsonify({"error": "cross-origin request refused"}), 403
    if not _host_allowed():
        return jsonify({"error": "host not allowed: set SPYGLASS_PRO_ALLOWED_HOSTS "
                                  "to permit it"}), 400
    if not _authorized():
        return jsonify({"error": "unauthorized: set SPYGLASS_PRO_TOKEN and send it as a Bearer token"}), 401


@app.after_request
def _security_headers(resp):
    """Baseline browser hardening.

    ``connect-src 'self'`` matches the dashboard, which only ever fetches its
    own /api/; ``img-src`` still allows remote avatars (the social panels
    render them straight from the platform CDNs). ``style-src`` allows inline
    styles because the shell uses a ``style`` attribute — there is no inline
    script, so ``script-src`` stays strict.
    """
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    resp.headers.setdefault("Content-Security-Policy", (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com https://cdn.jsdelivr.net data:; "
        "img-src 'self' data: https:; "
        "connect-src 'self'; "
        "object-src 'none'; base-uri 'self'; form-action 'self'; "
        "frame-ancestors 'none'"
    ))
    return resp


@app.route("/")
def index():
    """Render the dashboard.

    ``version`` and ``keys_total`` come from the server so the markup can
    never drift from ``version.py`` / ``_SETTINGS_SPEC`` — the JS only
    *updates* these two values after ``/api/status`` and ``/api/settings``
    resolve, and the first paint shows the truth.
    """
    return render_template("index.html", version=__version__,
                           keys_total=len(_SETTINGS_SPEC))


@app.route("/api/status")
def api_status():
    """Engines, social platforms, and the optional CLI tools behind them.

    Two vocabularies exist and the UI needs both: *engines* are the vendored
    packages that can fail to import, *platforms* are the adapters inside the
    social harness. Reporting only the first made "INSTA" in the topbar a lie
    once Instagram became a platform rather than an engine.

    The engines resolve their tools with ``shutil.which`` at *import* time,
    so a tool installed after the server started would stay invisible. Probe
    the names again here — the lookup rules mirror ``spyglass_osint.utils``.
    """
    tools = {name: bool(_which_any(*candidates))
             for name, candidates in _TOOL_PROBES.items()}
    # Blackbird is the one tool the engine resolves beyond PATH.
    tools["blackbird"] = _blackbird_present()
    platforms = []
    try:
        platforms = runner.social_platforms()
    except Exception:
        platforms = []
    with runner._JOB_LOCK:
        pending = runner._PENDING
    return jsonify({
        "status": "ok",
        "version": __version__,
        "proxy": _mask_proxy(os.environ.get("SPYGLASS_PROXY", "")),
        "engines": {
            "spyglass": {"available": True, "label": "Spyglass-OSINT"},
            "social": {"available": _module_imports("instacloak"),
                       "label": "Social harness"},
        },
        "platforms": platforms,
        "tools": tools,
        "missing_tools": sorted(name for name, found in tools.items() if not found),
        "degraded": _degraded(tools),
        "queue": {"pending": pending, "max_queue": runner.MAX_QUEUE,
                  "workers": 3, "social_workers": 1},
    })


def _which_any(*names):
    return next((shutil.which(name) for name in names if shutil.which(name)), None)


def _blackbird_present():
    """Blackbird detection matching the engine's own resolution.

    The engine (spyglass_osint.utils) falls back to fixed clone layouts
    when the name is not on PATH; the status probe must do the same or
    the dashboard reports a tool missing that scans would actually use.
    """
    if _which_any("blackbird", "blackbird.py"):
        return True
    try:
        from spyglass_osint.utils import _BLACKBIRD_PATHS
    except Exception:
        return False
    return any(os.path.isfile(path) for path in _BLACKBIRD_PATHS)


def _module_imports(name):
    """A module is available when its package imports (deps present)."""
    try:
        importlib.import_module(name)
        return True
    except Exception:
        return False


# Recon legs each query type cannot run without, beyond its keyless core:
# *everything else that module does still runs*. Mirrored by the UI's
# per-module data-source grid (``app.js`` ``TOOL_ROWS``) — pinned by
# tests/test_ui_contract.py, so the two tables cannot drift apart.
_TOOLS_LEGS = {
    "email": ["holehe", "user-scanner", "blackbird"],
    "username": ["user-scanner", "sherlock", "maigret", "blackbird"],
    "phone": ["ignorant", "phoneinfoga"],
    # Light website only: owner/registrant, WHOIS, DNS and CT. `curl` went
    # with the page/header fetch.
    "website": ["dig", "whois"],
    "metadata": ["exiftool"],
}


def _degraded(tools):
    """Which recon legs each query type cannot run right now.

    A missing tool does not fail the scan — the engine skips that leg and
    returns the rest — so the UI has to say so, or a partial result reads
    as a complete one.
    """
    legs = _TOOLS_LEGS
    return {qtype: [tool for tool in needed if not tools.get(tool)]
            for qtype, needed in legs.items()
            if any(not tools.get(tool) for tool in needed)}


# ─── API key settings (vault) ───────────────────────────────────
#
# The dark-web keyed layers read INTELX_API_KEY / HIBP_API_KEY from the
# environment. The dashboard edits them through one endpoint so operators
# never hand-edit files. GET masks values (configured + last-4 hint only);
# POST writes non-empty values and clears on empty string.
#
# Storage lives in spyglass_pro.vault (~/.spyglass/vault.json, 0600 on
# POSIX). It used to live in the vendored Lens engine's config file; that
# coupling would have broken Settings the day Lens was cut out of this
# tree — which is exactly what happened — so the vault owns its file and
# imports the old values once.
#
# Only the keys an exposed module actually reads are offered here. The
# removed IP/Lens infrastructure had its own keys (Shodan, VirusTotal,
# AbuseIPDB, Censys, GreyNoise, NVD); they stayed in the legacy config
# file and are not part of this build's Settings surface.

_SETTINGS_SPEC = [
    {"key": "intelx_api_key", "label": "IntelX", "env": "INTELX_API_KEY",
     "help": "Breach + paste archive search"},
    {"key": "hibp_api_key", "label": "HIBP", "env": "HIBP_API_KEY",
     "help": "Authoritative breach list"},
]


def _settings_store():
    """The storage backend for Settings.

    A module with ``load()``/``save()``. Returning None means "no
    persistence available" — the endpoints then keep working against
    environment variables only, which is what a read-only home does.
    """
    try:
        from . import vault
        return vault
    except ImportError:
        return None


def _settings_snapshot():
    store = _settings_store()
    cfg = store.load() if store else {}
    items = []
    for spec in _SETTINGS_SPEC:
        val = (cfg.get(spec["key"]) or os.environ.get(spec["env"]) or "").strip()
        items.append({
            "key": spec["key"], "label": spec["label"], "help": spec["help"],
            "configured": bool(val),
            "hint": ("••••" + val[-4:]) if len(val) > 4 else ("set" if val else ""),
        })
    return {"keys": items,
            "configured": sum(1 for i in items if i["configured"]),
            "total": len(items),
            "proxy": _mask_proxy(os.environ.get("SPYGLASS_PROXY", ""))}


@app.route("/api/settings")
def api_settings():
    return jsonify(_settings_snapshot())


@app.route("/api/settings", methods=["POST"])
def api_settings_save():
    data = request.get_json(silent=True) or {}
    if not isinstance(data, dict):
        return jsonify({"error": "invalid settings payload"}), 400
    store = _settings_store()
    cfg = store.load() if store else {}
    # Proxy rides along so Settings is the one place for outbound config.
    if "proxy" in data:
        raw = data.get("proxy", "")
        current = os.environ.get("SPYGLASS_PROXY", "")
        # The Settings box is pre-filled with the masked form (see
        # _settings_snapshot), so an untouched box posts the mask straight
        # back. Treat that — and only that — as "leave the proxy unchanged".
        if isinstance(raw, str) and current and raw.strip() == _mask_proxy(current):
            raw = current
        if isinstance(raw, str) and "••••" in raw:
            return jsonify({
                "error": "proxy contains the masked placeholder — re-enter the "
                         "full proxy URL (including credentials) to change it"
            }), 400
        proxy = _validate_proxy(raw)
        if proxy is None:
            return jsonify({"error": "invalid proxy URL"}), 400
        if proxy:
            for k in ("SPYGLASS_PROXY", "ALL_PROXY", "HTTP_PROXY", "HTTPS_PROXY"):
                os.environ[k] = proxy
        else:
            for k in ("SPYGLASS_PROXY", "ALL_PROXY", "HTTP_PROXY", "HTTPS_PROXY"):
                os.environ.pop(k, None)
        # The proxy is stored next to the API keys so one file holds every
        # outbound credential the dashboard owns.
        cfg["proxy"] = proxy
        cfg["socks_proxy"] = proxy
    updated, cleared = [], []
    by_key = {s["key"]: s for s in _SETTINGS_SPEC}
    for key, raw in data.items():
        if key == "proxy" or key not in by_key:
            continue
        val = (raw if isinstance(raw, str) else str(raw or "")).strip()
        if val:
            cfg[key] = val
            os.environ[by_key[key]["env"]] = val
            updated.append(key)
        else:
            cfg.pop(key, None)
            cfg[key] = ""
            os.environ.pop(by_key[key]["env"], None)
            cleared.append(key)
    if store:
        try:
            store.save({**store.load(), **{k: cfg.get(k, "") for k in
                                            [s["key"] for s in _SETTINGS_SPEC] + ["proxy", "socks_proxy"]}})
        except Exception as exc:
            return jsonify({"error": f"could not save settings: {exc}"}), 500
    snap = _settings_snapshot()
    snap.update({"updated": updated, "cleared": cleared, "status": "saved"})
    return jsonify(snap)


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
        return jsonify({"proxy": _mask_proxy(proxy), "status": "updated"})
    return jsonify({"proxy": _mask_proxy(os.environ.get("SPYGLASS_PROXY", ""))})


@app.route("/api/spyglass/run")
def api_spyglass_run():
    """Run one exposed Spyglass-OSINT module (email/username/phone/
    website/darkweb/opsec/metadata). Extra query params become module
    flags (json/csv/report/store, darkweb type hint)."""
    module = request.args.get("module", "")
    if not module:
        return jsonify({"error": "module parameter required"})
    # The scope list is the allowlist, not a comment: anything the runner
    # knows but this build does not expose is refused here. Without this a
    # new handler added to runner._SPYGLASS_HANDLERS would silently become
    # reachable over HTTP the moment it landed.
    if not scope.is_exposed_module(module):
        return jsonify({
            "error": f"unknown module: {module!r} — not part of this build"
        }), 400
    target = request.args.get("target", "")
    # ``token`` is an auth channel, not a module flag: it must not ride
    # into the engine, where a future flag consumer could echo it into a
    # result, a progress line or an artifact.
    flags = {key: value for key, value in request.args.items()
             if key not in ("module", "target", "async", "token")}
    return _submit_or_run(runner.run_spyglass, module, target, flags)


@app.route("/api/investigate/run", methods=["POST"])
def api_investigate_run():
    """Correlated multi-input investigation."""
    data = request.get_json(silent=True) or {}
    payload = dict(data) if isinstance(data, dict) else {}
    payload.pop("async", None)
    # _data carries the original for the async flag; payload is engine-clean.
    if _wants_async(data):
        result = runner.submit_job(runner.run_investigate, payload)
        if isinstance(result, dict) and result.pop(runner.REJECTED_KEY, False):
            return jsonify(result), 429
        return jsonify(result), 202
    return _submit_or_run(runner.run_investigate, payload)


@app.route("/api/social/platforms")
def api_social_platforms():
    """Platforms the social harness can collect, with their capabilities."""
    return jsonify(runner.social_platforms())


# ─── tracked targets (CHECK AGAIN) ────────────────────────
#
# Targets are managed entities, not form fields: they are added and
# removed here, and the social tabs only ever *check* one — the first
# check pins the baseline, later checks diff against it. Email, username
# and website searches keep their manual in-tab inputs: they are
# one-shot queries, not tracked identities.


def _social_tracking():
    """Lazy import — the dashboard must start without the social tree."""
    from spyglass_pro.social import tracking
    return tracking


@app.route("/api/social/targets", methods=["GET", "POST"])
def api_social_targets():
    """List every tracked target, or register one (platform + handle)."""
    tracking = _social_tracking()
    if request.method == "GET":
        try:
            return jsonify(tracking.list_targets())
        except Exception as exc:
            return jsonify({"error": f"target store unavailable: "
                                     f"{runner._safe_error(exc)}"}), 500
    data = request.get_json(silent=True) or {}
    platform = (data.get("platform") or "").strip()
    handle = (data.get("handle") or "").strip()
    if not platform or not handle:
        return jsonify({"error": "platform and handle are both required"}), 400
    from spyglass_pro.social import registry
    if registry.get(platform.lower()) is None:
        return jsonify({"error": f"unknown platform: {platform}"}), 400
    try:
        return jsonify(tracking.add_target(platform, handle)), 201
    except ValueError as exc:
        # Duplicates land here too: "already tracked" is a refusal of
        # *this* request, not a server fault — 400, not 500.
        return jsonify({"error": str(exc)}), 400


@app.route("/api/social/targets/<int:target_id>", methods=["GET", "DELETE"])
def api_social_target(target_id):
    """One target with its snapshot history, or forget it entirely."""
    tracking = _social_tracking()
    try:
        if request.method == "DELETE":
            if not tracking.remove_target(target_id):
                return jsonify({"error": f"unknown target #{target_id}"}), 404
            return jsonify({"deleted": target_id})
        target = tracking.get_target(target_id)
        if target is None:
            return jsonify({"error": f"unknown target #{target_id}"}), 404
        try:
            limit = int(request.args.get("limit", tracking.HISTORY_LIMIT))
        except (TypeError, ValueError):
            limit = tracking.HISTORY_LIMIT
        target["history"] = tracking.history(target_id, max(1, min(limit, 200)))
        # Every check's verdict, not just the newest: the dashboard's
        # timeline selects a past check, and its stats/diff must rewind to
        # that check. Same engine either way — a second, client-side diff
        # implementation is exactly how the UI starts claiming changes the
        # engine would refuse. ``last_diff`` keeps its old meaning.
        from spyglass_pro.social.diff import diff as _diff_payloads
        hist = target["history"]
        baseline_refusal = {
            "ok": False, "changed": False,
            "error": "no previous check to compare against — this run is the baseline",
        }
        for i, entry in enumerate(hist):
            if i + 1 < len(hist):
                entry["diff"] = _diff_payloads(hist[i + 1]["payload"],
                                               entry["payload"])
            else:
                entry["diff"] = dict(baseline_refusal)
        target["last_diff"] = hist[0]["diff"] if hist else None
        return jsonify(target)
    except Exception as exc:
        return jsonify({"error": runner._safe_error(exc)}), 500


# ─── Downloaded media (Instagram stories / post files) ─────────────
#
# Media paths live in the encrypted snapshots, but the browser needs bytes.
# Two rules keep that from becoming a file-read primitive:
#
# * only files referenced by *this* target's snapshots are served, so one
#   dashboard cannot read another target's downloads;
# * the resolved path must sit under a configured output root, so a
#   corrupted reference cannot reach the rest of the filesystem.

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _media_roots():
    roots = [os.path.join(os.getcwd(), "output"),
             os.path.join(_PROJECT_ROOT, "output")]
    configured = os.environ.get("INSTACLOAK_OUTPUT_DIR")
    if configured:
        roots.append(os.path.abspath(configured))
    out = []
    for root in roots:
        real = os.path.realpath(root)
        if real not in out:
            out.append(real)
    return out


def _canonical_media_candidates(ref):
    """Every real path one stored media reference could resolve to.

    The engine writes ``output/<handle>/…`` relative to the process cwd;
    a server launched from elsewhere still needs to find it, so relative
    references are tried against the cwd and the project root.
    """
    if not isinstance(ref, str) or not ref.strip():
        return []
    ref = ref.strip()
    candidates = ([ref] if os.path.isabs(ref)
                  else [os.path.join(base, ref)
                        for base in (os.getcwd(), _PROJECT_ROOT)])
    return [os.path.realpath(c) for c in candidates]


def _referenced_media(target_id):
    """Canonical paths referenced by this target's snapshots."""
    files = set()
    try:
        hist = _social_tracking().history(target_id)
    except Exception:
        return files
    for entry in hist:
        payload = entry.get("payload") or {}
        refs = list(payload.get("media_files") or [])
        for post in payload.get("posts") or []:
            if isinstance(post, dict):
                refs.extend(post.get("media_files") or [])
        stories = payload.get("stories")
        if isinstance(stories, dict):
            for item in stories.get("items") or []:
                if isinstance(item, dict) and item.get("file"):
                    refs.append(item["file"])
        for ref in refs:
            files.update(_canonical_media_candidates(ref))
    return files


def _resolve_media_path(target_id, requested):
    """The real path to serve, or None. Allowlist + root containment."""
    allowed = _referenced_media(target_id)
    roots = [root + os.sep for root in _media_roots()]
    for path in _canonical_media_candidates(requested):
        if path not in allowed:
            continue
        if not any(path.startswith(root) for root in roots):
            continue
        if os.path.isfile(path):
            return path
    return None


@app.route("/api/social/media/<int:target_id>")
def api_social_media(target_id):
    """Serve one downloaded file referenced by this target's snapshots."""
    if _social_tracking().get_target(target_id) is None:
        return jsonify({"error": f"unknown target #{target_id}"}), 404
    ref = (request.args.get("path") or "").strip()
    if not ref:
        return jsonify({"error": "path is required"}), 400
    path = _resolve_media_path(target_id, ref)
    if path is None:
        return jsonify({"error": "no such media file on this target"}), 404
    return send_file(path, conditional=True)



@app.route("/api/social/targets/<int:target_id>/check", methods=["POST"])
def api_social_target_check(target_id):
    """CHECK AGAIN: collect the target, diff it against its last check.

    Same transport contract as every other run route: blocking by
    default, ``?async=1`` (or ``{"async": 1}``) for 202 + job_id with
    ``/api/stream/<job_id>`` carrying live progress. Runs in the
    isolated SOCIAL_POOL so a browser collection never holds a generic
    scan worker. This replaces the old free-form ``/api/social/run``:
    checks only exist against tracked targets now.
    """
    raw = request.get_json(silent=True) or {}
    data = {k: v for k, v in raw.items() if k != "async"} if isinstance(raw, dict) else {}
    try:
        if _social_tracking().get_target(target_id) is None:
            return jsonify({"error": f"unknown target #{target_id}"}), 404
    except Exception as exc:
        return jsonify({"error": runner._safe_error(exc)}), 500
    return _submit_or_run(runner.check_social_target, target_id, data,
                          pool=runner.SOCIAL_POOL, _data=raw)


@app.route("/api/healthz")
def api_healthz():
    """Liveness + pool saturation for prod servers and load balancers."""
    with runner._JOB_LOCK:
        pending = runner._PENDING
    return jsonify({
        "status": "ok",
        "version": __version__,
        "queue": {"pending": pending, "max_queue": runner.MAX_QUEUE,
                  "workers": 3, "social_workers": 1,
                  "job_timeout": runner.JOB_TIMEOUT},
    })


@app.route("/api/jobs")
def api_jobs():
    """Newest-first snapshot of the async job registry (no full results)."""
    return jsonify(runner.list_jobs(request.args.get("limit", 50)))


@app.route("/api/job/<job_id>")
def api_job(job_id):
    """Poll one async job. 200 when done, 202 while running."""
    job = runner.get_job(job_id)
    err = job.get("error") or ""
    if err.startswith("unknown job"):
        return jsonify(job), 404
    if job.get("status") == "running":
        return jsonify(job), 202
    return jsonify(job)


@app.route("/api/job/<job_id>", methods=["DELETE"])
def api_job_forget(job_id):
    """Drop a finished job from the in-memory registry."""
    result = runner.forget_job(job_id)
    if "error" in result:
        code = 404 if "unknown job" in result["error"] else 409
        return jsonify(result), code
    return jsonify(result)


# ─── live run console (SSE) ─────────────────────────────────
#
# One open stream holds one WSGI worker thread for as long as the scan
# runs (up to JOB_TIMEOUT), so the number of concurrent streams is
# bounded like the job queue is: past the limit the client gets 429 and
# falls back to polling /api/job/<id>, which reports the same progress
# incrementally. Back-pressure, not a hidden thread pile-up.
_MAX_STREAMS = runner.env_number("SPYGLASS_PRO_MAX_STREAMS", 4, int, minimum=1)
_STREAM_LOCK = threading.Lock()
_ACTIVE_STREAMS = 0


def _sse(event, data):
    """One server-sent event frame."""
    return f"event: {event}\ndata: {json.dumps(data, default=str)}\n\n"


@app.route("/api/stream/<job_id>")
def api_stream(job_id):
    """Live progress for one async job as server-sent events.

    Events: ``meta`` on connect, ``log`` per progress line (replayed in
    order, then pushed while the scan runs), ``done`` carrying the final
    result payload, ``error`` if the job disappears mid-stream. A
    ``: ping`` comment roughly every 15s keeps proxies and the browser
    from idling the socket out.

    Like every /api/* route this sits behind the token gate. The
    dashboard streams with fetch() + Authorization header rather than
    EventSource, which cannot send one.
    """
    global _ACTIVE_STREAMS
    job = runner.get_job(job_id)
    if job.get("job_id") != job_id:
        return jsonify(job), 404
    with _STREAM_LOCK:
        if _ACTIVE_STREAMS >= _MAX_STREAMS:
            return jsonify({
                "error": f"stream limit reached ({_MAX_STREAMS} open) — "
                         f"poll /api/job/{job_id} instead"
            }), 429
        _ACTIVE_STREAMS += 1

    def generate():
        global _ACTIVE_STREAMS
        try:
            yield _sse("meta", {"job_id": job_id, "name": job.get("name"),
                                "status": job.get("status")})
            seen = 0
            beat = time.time()
            while True:
                current = runner.get_job(job_id)
                if current.get("job_id") != job_id:
                    # Pruned mid-stream (TTL or the 200-job cap): say so
                    # rather than silently closing on a half-finished view.
                    yield _sse("error", {"error": f"job disappeared: {job_id}"})
                    return
                lines = current.get("progress") or []
                while seen < len(lines):
                    yield _sse("log", {"n": seen + 1, "line": lines[seen]})
                    seen += 1
                if current.get("status") == "done":
                    yield _sse("done", current.get("result") or {})
                    return
                if time.time() - beat >= 15:
                    yield ": ping\n\n"
                    beat = time.time()
                runner.wait_progress(job_id, timeout=1.0)
        finally:
            with _STREAM_LOCK:
                _ACTIVE_STREAMS -= 1

    return Response(stream_with_context(generate()),
                    mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache, no-transform",
                             "X-Accel-Buffering": "no"})


@app.route("/api/cases")
def api_cases():
    """Stored cases from both tools' case stores."""
    return jsonify(runner.list_cases())


@app.route("/api/cases/run", methods=["DELETE"])
def api_cases_delete():
    """Delete one stored run (and its entity index rows) by id + qtype."""
    result = runner.delete_case(request.args.get("id", ""),
                                request.args.get("qtype", ""))
    if "error" in result:
        code = 404 if "no stored" in result["error"] else 400
        return jsonify(result), code
    return jsonify(result)


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
    """(host, port, debug) from the environment, with safe defaults.

    A junk port raises ``ValueError`` with the variable named — the
    caller (``run``) turns that into a one-line startup error instead of
    a traceback. Request-time callers (``_allowed_hosts``) catch it and
    fall back to loopback-only, which is the safe direction.
    """
    host = os.environ.get("SPYGLASS_PRO_HOST", "127.0.0.1")
    raw_port = os.environ.get("SPYGLASS_PRO_PORT", "5000")
    try:
        port = int(str(raw_port).strip())
    except ValueError:
        raise ValueError(
            f"SPYGLASS_PRO_PORT must be an integer (got {raw_port!r})"
        ) from None
    if not 1 <= port <= 65535:
        raise ValueError(
            f"SPYGLASS_PRO_PORT must be between 1 and 65535 (got {port})"
        )
    # Werkzeug debug mode ships an interactive traceback console that is
    # effectively arbitrary code execution. Off by default — opt in with
    # SPYGLASS_PRO_DEBUG=1 on a trusted, loopback-only deployment.
    debug = os.environ.get("SPYGLASS_PRO_DEBUG", "0") == "1"
    return host, port, debug


def serve_config():
    """(host, port, debug, server, threads) for prod-capable startup."""
    host, port, debug = bind_config()
    server = os.environ.get("SPYGLASS_PRO_SERVER", "auto").strip().lower()
    if server not in ("auto", "flask", "waitress"):
        server = "auto"
    threads = runner.env_number("SPYGLASS_PRO_THREADS", 8, int, minimum=1)
    return host, port, debug, server, threads


def run():
    try:
        host, port, debug, server, threads = serve_config()
    except ValueError as exc:
        # A config typo is an operator error, not a crash: name the
        # variable and exit non-zero instead of dumping a traceback.
        print(f"Spyglass-Pro: {exc}")
        raise SystemExit(2) from None
    if os.environ.get("SPYGLASS_PRO_TOKEN"):
        print("Spyglass-Pro: API token authentication enabled")
    elif host.lower() not in ("127.0.0.1", "localhost", "::1"):
        print("WARNING: binding to a non-loopback address without SPYGLASS_PRO_TOKEN — "
              "the dashboard and its scan engines are unauthenticated. "
              "Set SPYGLASS_PRO_TOKEN before exposing this server.")
        print("         Without a token the Host allowlist stays in force, so "
              "requests under this bind address need "
              "SPYGLASS_PRO_ALLOWED_HOSTS=<hostname-or-ip>.")
    use_waitress = server == "waitress" or (server == "auto" and not debug)
    if use_waitress:
        try:
            from waitress import serve as _serve
        except ImportError:
            _serve = None
        if _serve is not None:
            print(f"Spyglass-Pro serving (waitress, threads={threads}) "
                  f"on http://{host}:{port}")
            _serve(app, host=host, port=port, threads=threads)
            return
        if server == "waitress":
            print("Spyglass-Pro: waitress not installed (pip install waitress), "
                  "falling back to Flask dev server")
    app.run(host=host, port=port, debug=debug, threaded=True)

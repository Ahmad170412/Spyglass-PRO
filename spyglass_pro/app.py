import importlib
import json
import os
import secrets
import shutil
import threading
import time
from urllib.parse import urlparse

from flask import Flask, Response, jsonify, render_template, request, stream_with_context

from spyglass_pro import __version__, runner

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
    "shodan": ("shodan",),
    "exiftool": ("exiftool",),
    "curl": ("curl",),
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


@app.before_request
def _gate_api():
    if not _authorized():
        return jsonify({"error": "unauthorized: set SPYGLASS_PRO_TOKEN and send it as a Bearer token"}), 401


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
        "proxy": os.environ.get("SPYGLASS_PROXY", ""),
        "engines": {
            "spyglass": {"available": True, "label": "Spyglass-OSINT"},
            "lens_extender": {"available": _module_imports("lens_extender"),
                              "label": "Lens-Extender"},
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
    "website": ["dig", "whois", "curl"],
    "ip": ["shodan"],
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
# Lens-Extender reads ~/.lens-extender/config.json; dark-web keyed layers
# read INTELX_API_KEY / HIBP_API_KEY from the environment. The dashboard
# edits both through one endpoint so operators never hand-edit files.
# GET masks values (configured + last-4 hint only); POST writes non-empty
# values and clears on empty string. Keys at rest keep 0600 via le_config.

_SETTINGS_SPEC = [
    {"key": "shodan_api_key", "label": "Shodan", "env": "SHODAN_API_KEY",
     "help": "IP host data, open ports, org/ISP"},
    {"key": "virustotal_api_key", "label": "VirusTotal", "env": "VIRUSTOTAL_API_KEY",
     "help": "IP reputation, malicious votes"},
    {"key": "abuseipdb_api_key", "label": "AbuseIPDB", "env": "ABUSEIPDB_API_KEY",
     "help": "Abuse confidence score"},
    {"key": "censys_api_id", "label": "Censys ID", "env": "CENSYS_API_ID",
     "help": "Censys Search API identifier"},
    {"key": "censys_api_key", "label": "Censys Secret", "env": "CENSYS_API_KEY",
     "help": "Censys Search API secret"},
    {"key": "greynoise_api_key", "label": "GreyNoise", "env": "GREYNOISE_API_KEY",
     "help": "Internet-noise classification"},
    {"key": "nvd_api_key", "label": "NVD", "env": "NVD_API_KEY",
     "help": "CVE enrichment, higher rate limit"},
    {"key": "intelx_api_key", "label": "IntelX", "env": "INTELX_API_KEY",
     "help": "Breach + paste archive search"},
    {"key": "hibp_api_key", "label": "HIBP", "env": "HIBP_API_KEY",
     "help": "Authoritative breach list"},
]


def _settings_store():
    try:
        from lens_extender import config as le_config
        return le_config
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
            "proxy": os.environ.get("SPYGLASS_PROXY", "")}


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
        proxy = _validate_proxy(data.get("proxy", ""))
        if proxy is None:
            return jsonify({"error": "invalid proxy URL"}), 400
        if proxy:
            for k in ("SPYGLASS_PROXY", "ALL_PROXY", "HTTP_PROXY", "HTTPS_PROXY"):
                os.environ[k] = proxy
        else:
            for k in ("SPYGLASS_PROXY", "ALL_PROXY", "HTTP_PROXY", "HTTPS_PROXY"):
                os.environ.pop(k, None)
        # Persist for lens recon too.
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
             if key not in ("module", "target", "async")}
    return _submit_or_run(runner.run_spyglass, module, target, flags)


@app.route("/api/lens/run")
def api_lens_run():
    """Run Lens-Extender passive recon (Shodan, InternetDB, RDAP, ...)."""
    target = request.args.get("target", "")
    if not target:
        return jsonify({"error": "target required"})
    flags = {key: value for key, value in request.args.items()
             if key not in ("target", "async")}
    return _submit_or_run(runner.run_lens, target, flags)


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


@app.route("/api/social/run", methods=["POST"])
def api_social_run():
    """Collect one profile through the shared social harness."""
    raw = request.get_json(silent=True) or {}
    # Never forward the transport flag to the engine.
    data = {k: v for k, v in raw.items() if k != "async"} if isinstance(raw, dict) else {}
    platform = (data.get("platform") or "").strip()
    handle = (data.get("handle") or "").strip()
    if not platform:
        return jsonify({"error": "platform required"})
    if not handle:
        return jsonify({"error": "handle required"})
    return _submit_or_run(runner.run_social, platform, handle, data,
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
_MAX_STREAMS = max(1, int(os.environ.get("SPYGLASS_PRO_MAX_STREAMS", "4")))
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
    """(host, port, debug) from the environment, with safe defaults."""
    host = os.environ.get("SPYGLASS_PRO_HOST", "127.0.0.1")
    port = int(os.environ.get("SPYGLASS_PRO_PORT", "5000"))
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
    try:
        threads = max(1, int(os.environ.get("SPYGLASS_PRO_THREADS", "8")))
    except ValueError:
        threads = 8
    return host, port, debug, server, threads


def run():
    host, port, debug, server, threads = serve_config()
    if os.environ.get("SPYGLASS_PRO_TOKEN"):
        print("Spyglass-Pro: API token authentication enabled")
    elif host.lower() not in ("127.0.0.1", "localhost", "::1"):
        print("WARNING: binding to a non-loopback address without SPYGLASS_PRO_TOKEN — "
              "the dashboard and its scan engines are unauthenticated. "
              "Set SPYGLASS_PRO_TOKEN before exposing this server.")
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

"""Background run engine — wires the dashboard to the sibling tools.

Spyglass-Pro ships Spyglass-OSINT, InstaCloak and Lens-Extender as
plain packages under ``modules/``. This module puts that directory on
``sys.path`` and exposes one runner per tool plus a small job pool:

* each API endpoint submits its runner with :func:`run_job` and blocks
  on the future, so the existing fetch-then-render frontend contract
  stays unchanged (the pool bounds how many heavy scans run at once);
* runners collect progress lines from the tools' terminal UIs
  (InstaCloak hooks) or log callbacks (Lens) and return them as
  ``progress`` in the result JSON, next to a one-line ``summary``;
* unexpected failures come back as ``{"error": ...}`` so the dashboard
  always renders JSON.

The tools are imported lazily inside the runners: the dashboard must
start (and every other module must keep working) even when a tool's
optional dependencies (phonenumbers, httpx, cloakbrowser) are missing.
"""

from __future__ import annotations

import os
import re
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeoutError

# The three tools use relative imports internally (except lens_extender,
# which uses absolute `lens_extender.*` imports), so they must be
# importable as top-level packages.
MODULES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "modules")
if MODULES_DIR not in sys.path:
    sys.path.insert(0, MODULES_DIR)

# Bounded pool: a handful of concurrent heavy scans (sherlock, nmap,
# browser runs) is plenty; extra requests queue here instead of piling
# up subprocesses.
JOB_POOL = ThreadPoolExecutor(max_workers=3, thread_name_prefix="spyglass-job")

# Queue cap: heavy jobs (nmap runs 15 minutes at worst) must not
# pile up unboundedly — a client that fires many requests gets
# rejected once the pending queue is full instead of stalling the
# whole server behind a mountain of scans.
MAX_QUEUE = max(1, int(os.environ.get("SPYGLASS_PRO_MAX_QUEUE", "16")))
# Wall-clock budget per job. The underlying future keeps running
# (it cannot be cancelled mid-scan), but the requester is not held
# hostage by a hung scan.
JOB_TIMEOUT = float(os.environ.get("SPYGLASS_PRO_JOB_TIMEOUT", "900"))

_JOB_LOCK = threading.Lock()
_PENDING = 0


def _safe_error(exc):
    """Flatten an exception for a JSON response — no newlines,
    no multi-kilobyte tracebacks leaked to the client."""
    return " ".join(str(exc).split())[:300]


def run_job(fn, *args, **kwargs):
    """Run ``fn`` in the job pool and block until it finishes.

    Returns the runner's result dict; unexpected exceptions become
    ``{"error": ...}`` so the dashboard never sees a 500.
    """
    global _PENDING
    name = getattr(fn, "__name__", "job")
    with _JOB_LOCK:
        if _PENDING >= MAX_QUEUE:
            return {"error": f"{name} rejected: job queue full ({MAX_QUEUE} pending)"}
        _PENDING += 1

    def _done(_fut):
        global _PENDING
        with _JOB_LOCK:
            _PENDING -= 1

    try:
        fut = JOB_POOL.submit(fn, *args, **kwargs)
    except Exception as exc:
        with _JOB_LOCK:
            _PENDING -= 1
        return {"error": f"{name} rejected: {_safe_error(exc)}"}
    fut.add_done_callback(_done)
    try:
        return fut.result(timeout=JOB_TIMEOUT)
    except FutureTimeoutError:
        return {"error": f"{name} timed out after {int(JOB_TIMEOUT)}s "
                         "(the scan may still be running)"}
    except Exception as exc:
        return {"error": f"{name} failed: {_safe_error(exc)}"}


class Progress:
    """Collects progress lines from a tool's terminal UI."""

    def __init__(self):
        self.lines = []

    def add(self, msg):
        line = re.sub(r"\s+", " ", str(msg)).strip()
        if line:
            self.lines.append(line)


# ─── shared helpers ────────────────────────────────────────────

def _env_proxy():
    return os.environ.get("SPYGLASS_PROXY") or os.environ.get("ALL_PROXY")


def _apply_spyglass_proxy():
    """Point spyglass_osint's subprocess tooling at the dashboard proxy."""
    try:
        from spyglass_osint import utils
    except ImportError:
        return
    proxy = _env_proxy()
    if proxy:
        utils.set_proxy(proxy)


def _add_artifact(response, path, kind):
    if path:
        response.setdefault("artifacts", []).append(
            {"kind": kind, "path": str(path)}
        )


# ─── Spyglass-OSINT ────────────────────────────────────────────

def _sg_email(target, flags, progress):
    try:
        from spyglass_osint import email as mod
    except ImportError as exc:
        return {"error": f"email module unavailable: {exc}"}
    return _finish(mod.email(target), "email", target, flags, progress)


def _sg_username(target, flags, progress):
    try:
        from spyglass_osint import username as mod
    except ImportError as exc:
        return {"error": f"username module unavailable: {exc}"}
    return _finish(mod.username(target), "username", target, flags, progress)


def _sg_phone(target, flags, progress):
    try:
        from spyglass_osint import phone as mod
    except ImportError as exc:
        return {"error": f"phone module unavailable: {exc} (pip install phonenumbers)"}
    return _finish(mod.phone(target), "phone", target, flags, progress)


def _sg_website(target, flags, progress):
    try:
        from spyglass_osint import website as mod
    except ImportError as exc:
        return {"error": f"website module unavailable: {exc}"}
    return _finish(mod.website(target), "website", target, flags, progress)


def _sg_darkweb(target, flags, progress):
    try:
        from spyglass_osint import darkweb as mod
    except ImportError as exc:
        return {"error": f"darkweb module unavailable: {exc}"}
    # The darkweb form's type selector hints the query class.
    return _finish(mod.darkweb(target, qtype=flags.get("type") or None),
                   "darkweb", target, flags, progress)


def _sg_ip(target, flags, progress):
    try:
        from spyglass_osint import ip as mod
    except ImportError as exc:
        return {"error": f"ip module unavailable: {exc}"}
    return _finish(mod.address(target, top_ports=flags.get("ports") or None),
                   "ip", target, flags, progress)


def _sg_opsec(target, flags, progress):
    try:
        from spyglass_osint import opsec as mod
    except ImportError as exc:
        return {"error": f"opsec module unavailable: {exc}"}
    # Health check runs against the local machine — no target needed.
    return _finish(mod.health_check(), "opsec", target or "self", flags, progress)


def _sg_metadata(target, flags, progress):
    try:
        from spyglass_osint import metadata as mod
    except ImportError as exc:
        return {"error": f"metadata module unavailable: {exc}"}
    return _finish(mod.extract(target), "metadata", target, flags, progress)


_SPYGLASS_HANDLERS = {
    "email": _sg_email,
    "username": _sg_username,
    "phone": _sg_phone,
    "website": _sg_website,
    "darkweb": _sg_darkweb,
    "ip": _sg_ip,
    "opsec": _sg_opsec,
    "metadata": _sg_metadata,
}


def run_spyglass(module, target, flags):
    """Dispatch one spyglass_osint module run."""
    module = (module or "").strip()
    target = (target or "").strip()
    flags = flags or {}
    handler = _SPYGLASS_HANDLERS.get(module)
    if handler is None:
        return {"error": f"unknown module: {module}"}
    progress = Progress()
    progress.add(f"starting {module} recon for {target or '(self)'}")
    _apply_spyglass_proxy()
    try:
        result = handler(target, flags, progress)
        if isinstance(result, dict) and "error" in result:
            progress.add(f"{module} recon failed: {result['error']}")
        else:
            progress.add(f"{module} recon complete")
        return result
    except Exception as exc:
        progress.add(f"{module} recon failed: {exc}")
        return {"error": f"spyglass {module} failed: {_safe_error(exc)}"}


def _finish(result, qtype, target, flags, progress):
    """Merge export/store artifacts and progress into a module result."""
    response = dict(result) if isinstance(result, dict) else {"result": result}

    # Exporting or storing an error snapshot is noise — skip it.
    if not (isinstance(result, dict) and "error" in result):
        try:
            from spyglass_osint import export, store
            from spyglass_osint import report as report_mod
            if flags.get("json"):
                _add_artifact(response, export.json_output(result, target, qtype), "json")
            if flags.get("csv"):
                _add_artifact(response, export.csv_output(result, target, qtype), "csv")
            if flags.get("report"):
                _add_artifact(response, report_mod.write_report(result, qtype, target), "report")
            if flags.get("store"):
                run_id = store.store_result(result, qtype, target)
                if run_id:
                    response["stored_run_id"] = run_id
        except Exception as exc:
            response["artifact_error"] = _safe_error(exc)

    response["progress"] = progress.lines
    response["summary"] = _spyglass_summary(qtype, target, result)
    return response


def _count_platforms(result):
    """Count {'domain': ...} entries across a result's list values."""
    total = 0
    for value in result.values():
        if isinstance(value, list):
            total += sum(1 for item in value
                         if isinstance(item, dict) and item.get("domain"))
    return total


def _spyglass_summary(qtype, target, result):
    """One-line overview of a module result for the dashboard header."""
    if not isinstance(result, dict):
        return f"{qtype} recon for {target}"
    if "error" in result:
        return f"{qtype} recon for {target} — error"

    detail = ""
    if qtype in ("email", "username"):
        found = _count_platforms(result)
        detail = (f"{found} platform(s) with accounts" if found
                  else "no matching accounts found")
    elif qtype == "phone":
        pi = result.get("phonenumbers")
        if isinstance(pi, dict):
            bits = [str(pi[k]) for k in ("country", "region", "carrier", "line_type")
                    if pi.get(k)]
            detail = " — ".join(bits[:3])
        if not detail:
            detail = "carrier/geo + breach check complete"
    elif qtype == "website":
        subs = result.get("subdomains") or []
        detail = f"{len(subs)} subdomain(s) found" if subs else "DNS/WHOIS recon complete"
    elif qtype == "ip":
        parts = []
        ports = result.get("open_ports") or []
        if ports:
            parts.append(f"{len(ports)} open port(s)")
        geo = result.get("geo")
        if isinstance(geo, dict):
            loc = geo.get("city") or geo.get("country") or geo.get("Country")
            if loc:
                parts.append(str(loc))
        elif isinstance(geo, str) and geo:
            parts.append(geo)
        detail = ", ".join(parts)
    elif qtype == "darkweb":
        hits = len(result.get("ahmia") or [])
        detail = f"{hits} dark-web hit(s)" if hits else "no dark-web hits"
    elif qtype == "metadata":
        detail = f"{len(result)} metadata field(s) extracted"
    elif qtype == "opsec":
        recs = result.get("recommendations") or []
        detail = f"{len(recs)} recommendation(s)" if recs else "no issues detected"

    base = f"{qtype.capitalize()} recon for {target}"
    return f"{base} — {detail}" if detail else base


# ─── InstaCloak ────────────────────────────────────────────────

def _patch_instacloak_ui(progress):
    """Redirect every loaded instacloak module's UI helpers to progress.

    The modules bind ``say``/``say_parts``/``section`` into their own
    namespaces at import time (``from .ui import say``), so each module's
    binding has to be patched individually — patching ``instacloak.ui``
    alone would not reach call sites.
    """

    def say(msg, *styles, **kwargs):
        progress.add(msg)

    def say_parts(*parts, **kwargs):
        text = "".join(
            str(part[0]) if isinstance(part, tuple) else str(part)
            for part in parts
        )
        progress.add(text)

    def section(n, total, msg, **kwargs):
        progress.add(f"[{n}/{total}] {msg}")

    hooks = {"say": say, "say_parts": say_parts, "section": section}
    saved = []
    for name, mod in list(sys.modules.items()):
        if name == "instacloak" or name.startswith("instacloak."):
            for attr, hook in hooks.items():
                if getattr(mod, attr, None) is not None:
                    saved.append((mod, attr, getattr(mod, attr)))
                    setattr(mod, attr, hook)
    return saved


def _restore_instacloak_ui(saved):
    for mod, attr, original in saved:
        setattr(mod, attr, original)


# InstaCloak drives a real browser and patches the UI hooks of every
# loaded instacloak module process-wide (sys.modules attributes), so
# concurrent runs would cross their progress lines. One run at a time;
# other jobs (spyglass/lens) keep the pool's remaining workers.
_INSTACLOAK_LOCK = threading.Lock()


def run_instacloak(username, payload):
    """Run one InstaCloak profile collection."""
    payload = payload or {}
    username = (username or "").strip()
    if not username:
        return {"error": "username required"}
    progress = Progress()

    try:
        from instacloak import config as ic_config
        from instacloak import engine as ic_engine
    except ImportError as exc:
        return {"error": f"InstaCloak unavailable: {exc}"}

    with _INSTACLOAK_LOCK:
        return _run_instacloak(username, payload, ic_config, ic_engine, progress)


def _run_instacloak(username, payload, ic_config, ic_engine, progress):
    cfg = ic_config.load_config(None)
    # The form's checkboxes reflect the operator's current intent —
    # apply them directly over whatever config.toml says.
    cfg["headless"] = bool(payload.get("headless"))
    cfg["deep"] = bool(payload.get("deep"))
    cfg["download_media"] = bool(payload.get("media"))
    cfg["attempt_followers"] = bool(payload.get("followers"))

    # Burner login: credentials from the form win over config.toml.
    if payload.get("burner_enabled"):
        cfg["login_enabled"] = True
        cfg["login_username"] = ((payload.get("burner_username") or "").strip()
                                 or cfg["login_username"])
        cfg["login_password"] = (payload.get("burner_password")
                                 or cfg["login_password"])

    # Route the browser through the dashboard proxy when one is set.
    proxy = _env_proxy()
    if proxy:
        cfg["proxy_enabled"] = True
        cfg["proxy_url"] = proxy

    saved = _patch_instacloak_ui(progress)
    try:
        progress.add(f"starting instacloak collection for @{username}")
        report = ic_engine.collect(cfg, username)
    except SystemExit as exc:
        # open_session() exits when cloakbrowser is missing.
        return {
            "error": "InstaCloak could not launch a browser session "
                     f"(exit {exc.code}). Install cloakbrowser: pip install cloakbrowser"
        }
    except ImportError as exc:
        return {"error": f"InstaCloak dependency missing: {exc}"}
    except Exception as exc:
        return {"error": f"InstaCloak run failed: {_safe_error(exc)}"}
    finally:
        _restore_instacloak_ui(saved)

    response = dict(report) if isinstance(report, dict) else {"report": report}
    response["report_dir"] = str(ic_engine.output_dir(cfg, username))
    if payload.get("store"):
        # InstaCloak has no store of its own — the encrypted Spyglass
        # case store takes the report snapshot (qtype "instacloak").
        try:
            from spyglass_osint import store as sg_store
            run_id = sg_store.store_result(report, "instacloak", username)
            if run_id:
                response["stored_run_id"] = run_id
        except Exception:
            pass
    response["progress"] = progress.lines
    response["summary"] = _instacloak_summary(report, username)
    return response


def _instacloak_summary(report, username):
    if not isinstance(report, dict):
        return f"InstaCloak scan of @{username} complete"
    parts = []
    status = report.get("profile_status")
    if status and status != "ok":
        parts.append(f"profile: {status}")
    counts = (report.get("profile") or {}).get("counts") or {}
    for key, label in (("followers", "followers"), ("following", "following"),
                       ("posts", "posts")):
        value = counts.get(key)
        if value is not None:
            parts.append(f"{value} {label}")
    detail = ", ".join(parts)
    base = f"InstaCloak scan of @{username} complete"
    return f"{base} — {detail}" if detail else base


# ─── Lens-Extender ─────────────────────────────────────────────

def run_lens(target, flags):
    """Run Lens-Extender passive recon, optionally with an nmap scan."""
    flags = flags or {}
    target = (target or "").strip()
    if not target:
        return {"error": "target required"}
    progress = Progress()

    try:
        from lens_extender import analyzer as le_analyzer
        from lens_extender import config as le_config
        from lens_extender import osint as le_osint
        from lens_extender import scanner as le_scanner
        from lens_extender import store as le_store
    except ImportError as exc:
        return {"error": f"Lens-Extender unavailable: {exc} (pip install httpx)"}

    cfg = le_config.load()

    progress.add(f"starting lens-extender recon for {target}")

    def log_cb(line):
        # Log lines carry rich markup like "[green]GeoIP[/green] lookup OK".
        text = re.sub(r"\[/?[^\]]+\]", "", str(line)).strip()
        progress.add(text)

    try:
        osint_result = le_osint.gather(target, cfg, log_cb)
    except ValueError as exc:
        # Unresolvable domains raise ValueError with a clean message.
        return {"error": _safe_error(exc)}
    except Exception as exc:
        return {"error": f"passive recon failed: {_safe_error(exc)}"}

    scan_type = "passive"
    scan_result = None
    if flags.get("active"):
        scan_type = "active"
        scan_ip = osint_result.resolved_ip or target
        try:
            scan_result = le_scanner.scan(
                scan_ip,
                log_cb,
                tor=bool(flags.get("tor")),
                ports=flags.get("ports") or None,
            )
        except Exception as exc:
            progress.add(f"active scan failed: {exc}")

    try:
        report = le_analyzer.build_report(target, osint_result, scan_result)
    except Exception as exc:
        return {"error": f"report build failed: {_safe_error(exc)}"}
    progress.add(f"lens-extender {scan_type} scan complete")

    if flags.get("store"):
        le_store.store_scan(target, report, scan_type=scan_type)

    response = dict(report) if isinstance(report, dict) else {"report": report}
    response["progress"] = progress.lines
    response["summary"] = _lens_summary(report, target)
    return response


def _lens_summary(report, target):
    if not isinstance(report, dict):
        return f"Lens scan of {target} complete"
    parts = []
    ip = report.get("resolved_ip")
    if ip:
        parts.append(f"resolves to {ip}")
    ports = report.get("ports") or []
    if ports:
        parts.append(f"{len(ports)} open port(s)")
    vulns = report.get("vulns") or []
    if vulns:
        parts.append(f"{len(vulns)} vuln(s)")
    detail = ", ".join(parts)
    base = f"Lens scan of {target} complete"
    return f"{base} — {detail}" if detail else base


# ─── Cross-tool investigation ──────────────────────────────────

_INVESTIGATE_CORE_KEYS = ("email", "username", "phone", "website")


def run_investigate(payload):
    """Correlated multi-input investigation, with optional IP/Instagram legs."""
    payload = payload or {}
    progress = Progress()

    try:
        from spyglass_osint import investigation
    except ImportError as exc:
        return {"error": f"Spyglass-OSINT unavailable: {exc}"}
    _apply_spyglass_proxy()

    inputs = {key: (payload.get(key) or "").strip()
              for key in _INVESTIGATE_CORE_KEYS}
    inputs = {key: value for key, value in inputs.items() if value}
    if not inputs:
        return {"error": "provide at least one email, username, phone or website"}

    progress.add("running parallel recon (email / username / phone / website)")
    try:
        result = investigation.investigate(inputs)
    except Exception as exc:
        return {"error": f"investigation failed: {_safe_error(exc)}"}

    # Optional cross-tool legs: passive IP recon via Lens, Instagram
    # profiling via InstaCloak. Each runner brings its own progress.
    ip_target = (payload.get("ip") or "").strip()
    if ip_target:
        result["ip_recon"] = run_lens(ip_target, {"passive": "1"})
    insta_target = (payload.get("insta") or "").strip()
    if insta_target:
        result["instacloak"] = run_instacloak(insta_target, {})

    result["progress"] = progress.lines
    result["summary"] = _investigate_summary(inputs, result)
    return result


def _investigate_summary(inputs, result):
    parts = []
    entities = result.get("entities") or {}
    for key, label in (("emails", "email(s)"), ("domains", "domain(s)"),
                       ("ips", "IP(s)"), ("phones", "phone(s)"),
                       ("orgs", "org(s)")):
        values = entities.get(key) or []
        if values:
            parts.append(f"{len(values)} {label}")
    matches = sum(1 for corr in (result.get("correlations") or [])
                  if isinstance(corr, dict) and corr.get("type") == "match")
    if matches:
        parts.append(f"{matches} correlation(s)")
    detail = ", ".join(parts)
    base = "Investigation complete for " + ", ".join(inputs.values())
    return f"{base} — {detail}" if detail else base


# ─── Case history (both tools' SQLite stores) ──────────────────

def list_cases(limit=200):
    """Merge stored cases from both tools' stores.

    Shape matches the dashboard's case table:
    ``{id, target, qtype, run_at}``. Reads the runs/scans tables
    directly because the tools' own list APIs aggregate differently
    (spyglass groups by target/qtype; lens lists targets only).
    """
    cases = _spyglass_cases(limit) + _lens_cases(limit)
    cases.sort(key=lambda case: case.get("run_at") or "", reverse=True)
    return cases[:limit]


def _spyglass_cases(limit):
    # Private helpers on purpose: they own the SPYGLASS_HOME path and
    # schema initialisation for this vendored copy.
    try:
        from spyglass_osint import store as sg_store
        db = sg_store._connect()
    except ImportError:
        return []
    try:
        sg_store._init(db)
        rows = db.execute(
            "SELECT id, target, qtype, run_at FROM runs "
            "ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [{"id": row["id"], "target": row["target"],
                 "qtype": row["qtype"], "run_at": row["run_at"]}
                for row in rows]
    except Exception:
        return []
    finally:
        db.close()


def _lens_cases(limit):
    try:
        from lens_extender import store as le_store
        conn = le_store._get_conn()
    except ImportError:
        return []
    try:
        rows = conn.execute(
            "SELECT id, target, scan_type, timestamp FROM scans "
            "ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [{"id": row["id"], "target": row["target"],
                 "qtype": f"lens_{row['scan_type']}",
                 "run_at": row["timestamp"]}
                for row in rows]
    except Exception:
        return []
    finally:
        conn.close()


# ─── Case queries (entity index) ───────────────────────────

def _spyglass_store():
    """The vendored spyglass_osint store, or None when it can't be loaded."""
    try:
        from spyglass_osint import store
        return store
    except ImportError:
        return None


def case_diff(target, qtype=None):
    """Entity-level delta between the two most recent stored runs.

    Read-only SQLite query against the entity index — cheap enough to
    answer inline rather than through the job pool.
    """
    target = (target or "").strip()
    if not target:
        return {"error": "target required"}
    store = _spyglass_store()
    if store is None:
        return {"error": "Spyglass-OSINT store unavailable"}
    qtype = (qtype or "").strip() or None
    try:
        return store.diff(target, qtype)
    except Exception as exc:
        return {"error": _safe_error(exc)}


def case_timeline(target, qtype=None):
    """Chronological entity snapshots for a target (oldest first)."""
    target = (target or "").strip()
    if not target:
        return {"error": "target required"}
    store = _spyglass_store()
    if store is None:
        return {"error": "Spyglass-OSINT store unavailable"}
    qtype = (qtype or "").strip() or None
    try:
        return {"target": target, "qtype": qtype, "runs": store.timeline(target, qtype)}
    except Exception as exc:
        return {"error": _safe_error(exc)}


def case_profile(target):
    """Merge the latest stored run per query type into one dossier dict."""
    target = (target or "").strip()
    if not target:
        return {"error": "target required"}
    store = _spyglass_store()
    if store is None:
        return {"error": "Spyglass-OSINT store unavailable"}
    try:
        return store.export_profile(target)
    except Exception as exc:
        return {"error": _safe_error(exc)}

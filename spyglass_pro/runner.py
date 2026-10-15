"""Background run engine — wires the dashboard to the recon engines.

Spyglass-Pro ships Spyglass-OSINT, InstaCloak and Lens-Extender as
plain packages under ``modules/``, and its own social harness in
``social/``. This module puts the vendored directory on ``sys.path`` and
exposes one runner per engine plus a small job pool:

* each API endpoint submits its runner with :func:`run_job` and blocks
  on the future, so the existing fetch-then-render frontend contract
  stays unchanged (the pool bounds how many heavy scans run at once);
* runners collect progress lines from the engines' own terminal UIs or
  log callbacks and return them as ``progress`` in the result JSON, next
  to a one-line ``summary``;
* a finished response also carries ``normalized`` — a derived
  entities/facts/provenance block (see ``spyglass_pro.facts``) that gives
  every consumer one contract instead of three payload shapes;
* async jobs publish progress lines *as they happen* into their job
  record, so ``/api/stream`` can render a live run console;
* unexpected failures come back as ``{"error": ...}`` so the dashboard
  always renders JSON.

Browser-driven work is *not* dispatched from here: ``social.harness``
owns the stealth session and serializes it, so a platform scan and an
investigation's Instagram leg share one code path and one lock.

The engines are imported lazily inside the runners: the dashboard must
start (and every other module must keep working) even when an engine's
optional dependencies (phonenumbers, httpx, cloakbrowser) are missing.
"""

from __future__ import annotations

import os
import re
import sys
import sysconfig
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeoutError

# The three tools use relative imports internally (except lens_extender,
# which uses absolute `lens_extender.*` imports), so they must be
# importable as top-level packages.
MODULES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "modules")
if MODULES_DIR not in sys.path:
    sys.path.insert(0, MODULES_DIR)

# The engines find their CLI tools with ``shutil.which`` *at import time*,
# so anything pip-installed into this project's venv (holehe, sherlock,
# maigret, ignorant, user-scanner) is invisible unless the venv's script
# directory is on PATH. ``source .venv/bin/activate`` puts it there;
# ``.venv/bin/python run.py`` does not, and the recon legs silently skip
# themselves. Put it on PATH before any engine is imported.
_SCRIPTS_DIR = sysconfig.get_path("scripts")
if _SCRIPTS_DIR and os.path.isdir(_SCRIPTS_DIR):
    _path_parts = os.environ.get("PATH", "").split(os.pathsep)
    if _SCRIPTS_DIR not in _path_parts:
        os.environ["PATH"] = os.pathsep.join([_SCRIPTS_DIR] + [p for p in _path_parts if p])

# Bounded pool: a handful of concurrent heavy scans is plenty — a
# username sweep across sherlock/maigret, a breach check, a browser
# collection. Extra requests queue here instead of piling up work.
JOB_POOL = ThreadPoolExecutor(max_workers=3, thread_name_prefix="spyglass-job")

# Dedicated single worker for browser-driven social collection. The social
# harness serializes on its own lock already; giving it its own queue
# keeps a long Instagram collection from starving the 3 generic workers,
# and keeps a flood of generic scans from starving social.
SOCIAL_POOL = ThreadPoolExecutor(max_workers=1, thread_name_prefix="spyglass-social")

# Queue cap: heavy jobs (a full username sweep runs many minutes at
# worst) must not pile up unboundedly — a client that fires many
# requests gets rejected once the pending queue is full instead of
# stalling the whole server behind a mountain of scans.
MAX_QUEUE = max(1, int(os.environ.get("SPYGLASS_PRO_MAX_QUEUE", "16")))
# Wall-clock budget per job. The underlying future keeps running
# (it cannot be cancelled mid-scan), but the requester is not held
# hostage by a hung scan.
JOB_TIMEOUT = float(os.environ.get("SPYGLASS_PRO_JOB_TIMEOUT", "900"))

_JOB_LOCK = threading.Lock()
_PENDING = 0

# Thread-local progress sink. ``submit_job`` registers a per-job push
# function here for the duration of one job's execution, so a
# ``Progress`` created deep inside an engine still lands its lines in the
# job record while the scan runs — not only in the final payload.
_PROGRESS_HOOK = threading.local()


def _safe_error(exc):
    """Flatten an exception for a JSON response — no newlines,
    no multi-kilobyte tracebacks leaked to the client."""
    return " ".join(str(exc).split())[:300]


# Sentinel key marking a result as "the server refused this, try again later"
# rather than "the scan ran and failed". The Flask layer maps it to HTTP 429 so
# an API client can distinguish back-pressure from a real scan error, which a
# bare 200 carrying {"error": ...} does not allow.
REJECTED_KEY = "_rejected"


def _rejected(message):
    return {"error": message, REJECTED_KEY: True}


def run_job(fn, *args, **kwargs):
    """Run ``fn`` in the job pool and block until it finishes.

    Returns the runner's result dict; unexpected exceptions become
    ``{"error": ...}`` so the dashboard never sees a 500.
    """
    global _PENDING
    name = getattr(fn, "__name__", "job")
    with _JOB_LOCK:
        if _PENDING >= MAX_QUEUE:
            return _rejected(f"{name} rejected: job queue full ({MAX_QUEUE} pending)")
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


# ─── async job registry (non-blocking API) ───────────────────────
#
# run_job() above blocks the HTTP worker until the scan finishes. Under
# the Flask dev server — and under any threaded WSGI server — a handful
# of concurrent long scans (username sweeps run minutes) exhausts HTTP
# workers even though the pool already bounds scan concurrency.
#
# submit_job() instead queues the same runners and returns a job_id
# immediately; the caller polls get_job(). The HTTP thread is freed,
# the scan still honors MAX_QUEUE / JOB_TIMEOUT, and the sync API is
# untouched. Code-only: in-memory registry, no Redis, no Docker.
#
# Known limitation (documented, not hidden): a timed-out scan keeps its
# pool worker until the underlying function returns — Python threads
# cannot be killed. The HTTP caller is released; pool capacity is not.

_ASYNC_LOCK = threading.Lock()
_ASYNC_JOBS: dict = {}
_ASYNC_MAX_JOBS = max(1, int(os.environ.get("SPYGLASS_PRO_MAX_JOBS", "200")))
_ASYNC_TTL = float(os.environ.get("SPYGLASS_PRO_JOB_TTL", "3600"))

# One condition over the job registry: progress pushers and finished-job
# callbacks notify it, stream readers wait on it (bounded, so a missed
# notification costs one timeout, never a hung socket).
_PROGRESS_COND = threading.Condition(_ASYNC_LOCK)


def _prune_jobs(now=None):
    now = now if now is not None else time.time()
    with _ASYNC_LOCK:
        ids = list(_ASYNC_JOBS.keys())
        for job_id in ids:
            job = _ASYNC_JOBS.get(job_id)
            if job and (now - job.get("created_at", now)) > _ASYNC_TTL:
                _ASYNC_JOBS.pop(job_id, None)
        # Hard cap: drop oldest finished first, then oldest overall.
        while len(_ASYNC_JOBS) > _ASYNC_MAX_JOBS:
            oldest = min(_ASYNC_JOBS.items(),
                         key=lambda kv: (kv[1].get("status") == "running",
                                         kv[1].get("created_at", 0)))
            _ASYNC_JOBS.pop(oldest[0], None)


def submit_job(fn, *args, pool=None, **kwargs):
    """Queue ``fn`` and return ``{"job_id": ..., "status": "running"}``.

    Honors the same MAX_QUEUE back-pressure as run_job(); a full queue
    returns ``{"error": ...}`` with REJECTED_KEY so Flask maps it to 429.
    """
    global _PENDING
    name = getattr(fn, "__name__", "job")
    target_pool = pool or JOB_POOL
    with _JOB_LOCK:
        if _PENDING >= MAX_QUEUE:
            return _rejected(f"{name} rejected: job queue full ({MAX_QUEUE} pending)")
        _PENDING += 1
    _prune_jobs()
    job_id = uuid.uuid4().hex
    job = {"job_id": job_id, "name": name, "status": "running",
           "created_at": time.time(), "result": None, "error": None,
           "progress": []}
    with _ASYNC_LOCK:
        _ASYNC_JOBS[job_id] = job

    def _push(line):
        """Append one live progress line to this job's record."""
        with _PROGRESS_COND:
            stored = _ASYNC_JOBS.get(job_id)
            if stored is None:  # pruned or already finished — nothing to do
                return
            stored.setdefault("progress", []).append(line)
            _PROGRESS_COND.notify_all()

    def _publish(*args, **kwargs):
        # Thread-local: only this job's worker sees the sink, so parallel
        # jobs never push into each other's records.
        _PROGRESS_HOOK.push = _push
        try:
            return fn(*args, **kwargs)
        finally:
            _PROGRESS_HOOK.push = None

    try:
        fut = target_pool.submit(_publish, *args, **kwargs)
    except Exception as exc:
        with _JOB_LOCK:
            _PENDING -= 1
        with _ASYNC_LOCK:
            _ASYNC_JOBS.pop(job_id, None)
        return {"error": f"{name} rejected: {_safe_error(exc)}"}

    def _finish_async(_fut):
        global _PENDING
        try:
            try:
                result = _fut.result(timeout=JOB_TIMEOUT)
            except FutureTimeoutError:
                result = {"error": f"{name} timed out after {int(JOB_TIMEOUT)}s "
                                   "(the scan may still be running)"}
            except Exception as exc:
                result = {"error": f"{name} failed: {_safe_error(exc)}"}
            with _PROGRESS_COND:
                stored = _ASYNC_JOBS.get(job_id)
                if stored is not None:
                    stored["status"] = "done"
                    stored["result"] = result
                    stored["finished_at"] = time.time()
                # Notify even when the job was pruned: a stream waiting on
                # this id must wake up and report it gone, not wait out its
                # timeout every cycle.
                _PROGRESS_COND.notify_all()
        finally:
            with _JOB_LOCK:
                _PENDING -= 1

    fut.add_done_callback(_finish_async)
    return {"job_id": job_id, "status": "running", "name": name}


def get_job(job_id):
    """Return a snapshot of the stored job dict, or ``{"error": ...}``.

    ``progress`` is copied: a stream reader must be able to iterate it
    while the job's worker is still appending.
    """
    job_id = (job_id or "").strip()
    if not job_id:
        return {"error": "job_id required"}
    with _ASYNC_LOCK:
        job = _ASYNC_JOBS.get(job_id)
        if job is None:
            return {"error": f"unknown job: {job_id}"}
        out = dict(job)
        out["progress"] = list(job.get("progress") or [])
        return out


def wait_progress(job_id, timeout=1.0):
    """Block until this job pushes a progress line, finishes, or the
    timeout elapses. Returns False when the job no longer exists.

    Stream readers loop on this instead of busy-polling: a line arrives
    promptly, and a slow leg costs at most one timeout per check.
    """
    with _PROGRESS_COND:
        if job_id not in _ASYNC_JOBS:
            return False
        _PROGRESS_COND.wait(timeout)
        return True


def list_jobs(limit=50):
    """Newest-first snapshot of the in-memory job registry."""
    try:
        limit = max(1, min(int(limit), 200))
    except (TypeError, ValueError):
        limit = 50
    with _ASYNC_LOCK:
        jobs = list(_ASYNC_JOBS.values())
    jobs.sort(key=lambda j: j.get("created_at", 0), reverse=True)
    out = []
    for job in jobs[:limit]:
        entry = dict(job)
        # Do not ship full results in the list view — poll one job for that.
        if entry.get("result") is not None:
            entry["has_result"] = True
            entry.pop("result", None)
        out.append(entry)
    return out


def forget_job(job_id):
    """Drop a finished job from the registry. Running jobs are kept."""
    job_id = (job_id or "").strip()
    with _ASYNC_LOCK:
        job = _ASYNC_JOBS.get(job_id)
        if job is None:
            return {"error": f"unknown job: {job_id}"}
        if job.get("status") == "running":
            return {"error": "job is still running and cannot be forgotten"}
        _ASYNC_JOBS.pop(job_id, None)
        return {"job_id": job_id, "forgotten": True}


class Progress:
    """Collects progress lines from a tool's terminal UI.

    When the running job registered a sink (see ``submit_job``), each
    line is also pushed into the job record so ``/api/stream`` can show
    it live. Push failures must never fail the scan: the line is already
    collected locally either way.
    """

    def __init__(self):
        self.lines = []

    def add(self, msg):
        line = re.sub(r"\s+", " ", str(msg)).strip()
        if not line:
            return
        self.lines.append(line)
        push = getattr(_PROGRESS_HOOK, "push", None)
        if push is not None:
            try:
                push(line)
            except Exception:
                pass


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
    return _finish(mod.address(target), "ip", target, flags, progress)


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

# ─── target validation ───────────────────────────────────────────
#
# Recon targets are user input that ends up in subprocess arguments and in
# queries sent to third parties. Without a check, arbitrary junk is accepted:
# a 2KB garbage string reached the opsec panel and came back with confident
# "geo / ISP" data for the operator's own IP, and a 700-character string was
# handed to sherlock, which then held a worker for minutes. Both waste the
# worker pool and produce results that look authoritative but describe the
# wrong thing.
#
# Validation is per-module because the modules accept genuinely different
# shapes: opsec ignores its target and health-checks the local machine,
# metadata takes a filesystem path, and the rest take an identifier of a
# specific kind. A blanket "must look like a domain" rule would break the
# first two.

# Generous ceiling: no real email, handle, domain or phone number comes close.
MAX_TARGET_LEN = 254  # the DNS name limit, the longest of these shapes

_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9])?"
_DOMAIN_RE = re.compile(rf"^(?:{_LABEL}\.)+[A-Za-z]{{2,63}}$")
_EMAIL_RE = re.compile(rf"^[A-Za-z0-9._%+-]+@{_LABEL}(?:\.{_LABEL})+$")
_IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_SHELL_METACHARS = "<>\"'\\`;|&$(){}[]"


def _is_ipv4(value):
    """True for a dotted quad with every octet in 0-255 (utils has no checker)."""
    if not _IPV4_RE.match(value):
        return False
    return all(part.isdigit() and int(part) <= 255 for part in value.split("."))


def _is_identifier(value):
    """Email, phone (incl. international formats) or domain-shaped input."""
    if not value or len(value) > MAX_TARGET_LEN:
        return False
    if " " in value or any(ch in value for ch in _SHELL_METACHARS):
        return False
    if "@" in value:
        return bool(_EMAIL_RE.match(value))
    if _is_ipv4(value):
        return True
    # A phone number: digits, spaces, and the punctuation real formats use.
    digits = value.lstrip("+").replace(" ", "").replace("-", "")
    if digits.isdigit() and 5 <= len(digits) <= 15:
        return True
    return bool(_DOMAIN_RE.match(value))


def _validate_target(module, target):
    """Return an error string when (module, target) cannot be a real lookup.

    Empty targets are allowed only for the two modules that do not treat the
    target as a lookup key (opsec self-check, metadata file path) and are
    rejected everywhere else, which would otherwise silently query "".
    """
    if module == "opsec":
        # opsec never reads its target: _sg_opsec calls health_check(), which
        # inspects the local machine, and the target is only a case-store label.
        # A long value here is not a lookup key, it is junk that produced
        # authoritative-looking geo/ISP output about the operator's own IP.
        if len(target) > MAX_TARGET_LEN:
            return (f"opsec: target is ignored by this module and is too long "
                    f"({len(target)} characters); run it with no target")
        return None

    if module == "metadata":
        # metadata takes a filesystem path rather than an identifier.
        if target and len(target) > 4096:
            return f"metadata: path is implausibly long ({len(target)} characters)"
        return None

    if not target:
        return f"{module}: a target is required"

    if len(target) > MAX_TARGET_LEN:
        return (f"{module}: target is too long ({len(target)} characters, "
                f"maximum {MAX_TARGET_LEN})")

    if module == "ip":
        if not (_is_ipv4(target) or ":" in target):
            return f"ip: {target!r} is not an IP address"
        return None

    if module == "username":
        if not _USERNAME_RE.match(target):
            return f"username: {target!r} is not a valid username"
        return None

    if not _is_identifier(target):
        return f"{module}: {target!r} is not a valid {module} target"
    return None


def run_spyglass(module, target, flags):
    """Dispatch one spyglass_osint module run."""
    module = (module or "").strip()
    target = (target or "").strip()
    flags = flags or {}
    handler = _SPYGLASS_HANDLERS.get(module)
    if handler is None:
        return {"error": f"unknown module: {module}"}
    # Reject implausible targets before anything reaches a subprocess or a
    # third-party query — see _validate_target for why this is per-module.
    invalid = _validate_target(module, target)
    if invalid:
        return {"error": invalid}
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
    _attach_facts(response, qtype, target)
    return response


def _attach_facts(response, qtype, target):
    """Derive the normalized facts block onto a finished response.

    Called last so provenance sees the final summary/progress/artifacts.
    An errored response carries no normalized block (``normalize``
    returns None) — absence, not null filler, is "nothing was known". A
    failure *in the derived layer* keeps the raw payload intact and says
    so in ``facts_error``, the same contract exports use for
    ``artifact_error``.
    """
    if not isinstance(response, dict):
        return
    try:
        from spyglass_pro import facts as facts_mod
        block = facts_mod.normalize(response, qtype, target)
    except Exception as exc:
        response["facts_error"] = _safe_error(exc)
        return
    if block is not None:
        response["normalized"] = block


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


# ─── Lens-Extender ─────────────────────────────────────────────

def run_lens(target, flags):
    """Run Lens-Extender passive recon (Shodan, InternetDB, RDAP, …)."""
    flags = flags or {}
    target = (target or "").strip()
    if not target:
        return {"error": "target required"}
    # Lens targets are IPs or domains; the same junk-input problem applies.
    if not _is_identifier(target):
        return {"error": f"lens: {target!r} is not a valid IP or domain target"}
    progress = Progress()

    try:
        from lens_extender import analyzer as le_analyzer
        from lens_extender import config as le_config
        from lens_extender import osint as le_osint
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

    # Passive only: no scan_result, so the analyzer builds its port view
    # purely from Shodan and InternetDB. The active nmap path was removed
    # from this package.
    scan_type = "passive"
    try:
        report = le_analyzer.build_report(target, osint_result, None)
    except Exception as exc:
        return {"error": f"report build failed: {_safe_error(exc)}"}
    progress.add("lens-extender passive recon complete")

    stored_run_id = None
    if flags.get("store"):
        le_store.store_scan(target, report, scan_type=scan_type)
        stored_run_id = _lens_last_scan_id(target)

    response = dict(report) if isinstance(report, dict) else {"report": report}
    if stored_run_id:
        response["stored_run_id"] = stored_run_id
    response["progress"] = progress.lines
    response["summary"] = _lens_summary(report, target)
    _attach_facts(response, "lens", target)
    return response


def _lens_last_scan_id(target):
    """Row id of the scan just written, so the UI can refresh the case list."""
    try:
        from lens_extender import store as le_store
        conn = le_store._get_conn()
    except Exception:
        return None
    try:
        row = conn.execute(
            "SELECT id FROM scans WHERE target=? ORDER BY id DESC LIMIT 1", (target,)
        ).fetchone()
        return row["id"] if row else None
    except Exception:
        return None
    finally:
        conn.close()


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
    # The single-module path rejects junk before dispatch — the
    # investigation must too, or a 700-character "website" sails past the
    # gate straight into every engine.
    for key, value in inputs.items():
        invalid = _validate_target(key, value)
        if invalid:
            return {"error": invalid}

    progress.add("running parallel recon (email / username / phone / website)")
    try:
        result = investigation.investigate(inputs)
    except Exception as exc:
        return {"error": f"investigation failed: {_safe_error(exc)}"}

    # Optional cross-tool legs: passive IP recon via Lens, and a social
    # profile through the shared harness. Each leg brings its own progress.
    ip_target = (payload.get("ip") or "").strip()
    if ip_target:
        result["ip_recon"] = run_lens(ip_target, {"passive": "1"})
    insta_target = (payload.get("insta") or "").strip()
    if insta_target:
        result["social"] = run_social("instagram", insta_target, {}, progress=progress)

    result["progress"] = progress.lines
    result["summary"] = _investigate_summary(inputs, result)

    # The investigation panel's option checkboxes (json/csv/report/store)
    # arrive in the same payload as the target fields, so artifacts are
    # attached here rather than through _finish().
    if not (isinstance(result, dict) and "error" in result):
        try:
            from spyglass_osint import export, store
            from spyglass_osint import report as report_mod
            target = ", ".join(inputs.values())
            if payload.get("json"):
                _add_artifact(result, export.json_output(result, target, "investigation"), "json")
            if payload.get("csv"):
                _add_artifact(result, export.csv_output(result, target, "investigation"), "csv")
            if payload.get("report"):
                _add_artifact(result, report_mod.write_report(result, "investigation", target),
                              "report")
            if payload.get("store"):
                run_id = store.store_result(result, "investigation", target)
                if run_id:
                    result["stored_run_id"] = run_id
        except Exception as exc:
            result["artifact_error"] = _safe_error(exc)

    _attach_facts(result, "investigation", ", ".join(inputs.values()))
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


# ─── Multi-platform social (spyglass_pro.social) ─────────────

def social_platforms():
    """Platforms the social harness can collect, for the UI."""
    try:
        from spyglass_pro.social import registry
        return registry.describe()
    except Exception as exc:
        return {"error": _safe_error(exc)}


def run_social(platform, handle, payload, progress=None):
    """Collect one profile through the shared social harness.

    The harness owns the browser session and its serialization lock, so this
    is only option marshalling and artifact writing.
    """
    payload = payload or {}
    platform = (platform or "").strip().lower()
    handle = (handle or "").strip().lstrip("@")
    own_progress = progress is None
    progress = progress if progress is not None else Progress()

    try:
        from spyglass_pro.social import harness, registry
        from spyglass_pro.social import report as social_report
    except ImportError as exc:
        return {"error": f"social harness unavailable: {_safe_error(exc)}"}

    if registry.get(platform) is None:
        return {"error": f"unknown platform: {platform}"}
    if not handle:
        return {"error": "handle required"}
    # Handles ride into API URLs and directory names — same ceiling as
    # every other target so a megabyte handle cannot do either.
    if len(handle) > MAX_TARGET_LEN:
        return {"error": f"handle is too long ({len(handle)} characters, "
                         f"maximum {MAX_TARGET_LEN})"}

    options = {
        "headless": bool(payload.get("headless")),
        "deep": bool(payload.get("deep")),
        "media": bool(payload.get("media")),
        "proxy_url": _env_proxy(),
    }
    if payload.get("burner_enabled"):
        options["burner_username"] = (payload.get("burner_username") or "").strip()
        options["burner_password"] = payload.get("burner_password") or ""

    progress.add(f"starting {platform} collection for @{handle}")
    result = harness.collect(platform, handle, options, progress=progress)

    progress.add(social_report.summary(result))
    response = dict(result)
    response["progress"] = progress.lines if own_progress else []
    response["summary"] = social_report.summary(result)

    if not result.get("error"):
        try:
            from instacloak.session import safe_dir_name
            base = f"{platform}_{safe_dir_name(handle)}"
            if payload.get("report"):
                _add_artifact(response, social_report.write(
                    result, "output", f"{base}.md"), "report")
            if payload.get("json"):
                from spyglass_osint import export as sg_export
                _add_artifact(response, sg_export.json_output(
                    result, handle, f"social_{platform}"), "json")
        except Exception as exc:
            response["artifact_error"] = _safe_error(exc)
    _attach_facts(response, "social", handle)
    return response


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


def delete_case(run_id, qtype=""):
    """Delete one stored run (plus its entity index rows) by id.

    ``qtype`` picks the store: ``lens_*`` lives in the Lens scans table,
    everything else in the spyglass runs/entities tables. Done in the
    merge layer so the vendored engines stay untouched — same pattern as
    the list helpers above. Without this the case table only grows.
    """
    try:
        run_id = int(run_id)
    except (TypeError, ValueError):
        return {"error": "run id required"}
    if run_id <= 0:
        return {"error": "run id required"}
    qtype = (qtype or "").strip()
    if qtype.startswith("lens_"):
        try:
            from lens_extender import store as le_store
            conn = le_store._get_conn()
        except ImportError:
            return {"error": "Lens-Extender store unavailable"}
        try:
            cur = conn.execute("DELETE FROM scans WHERE id = ?", (run_id,))
            conn.commit()
            if not cur.rowcount:
                return {"error": f"no stored lens run #{run_id}"}
            return {"deleted": run_id, "qtype": qtype}
        except Exception as exc:
            return {"error": _safe_error(exc)}
        finally:
            conn.close()
    try:
        from spyglass_osint import store as sg_store
        db = sg_store._connect()
    except ImportError:
        return {"error": "Spyglass-OSINT store unavailable"}
    try:
        sg_store._init(db)
        # Explicit entity delete: SQLite only cascades with
        # PRAGMA foreign_keys=ON, which the store does not set.
        db.execute("DELETE FROM entities WHERE run_id = ?", (run_id,))
        cur = db.execute("DELETE FROM runs WHERE id = ?", (run_id,))
        db.commit()
        if not cur.rowcount:
            return {"error": f"no stored run #{run_id}"}
        return {"deleted": run_id, "qtype": qtype}
    except Exception as exc:
        return {"error": _safe_error(exc)}
    finally:
        db.close()


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

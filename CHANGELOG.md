# Changelog

Every entry is enforced by the offline suite (`python tests/run_tests.py`) —
the check counts quoted below are what the suite prints on a clean run.
Versions are read from `spyglass_pro/version.py` / `pyproject.toml`; those two
may not disagree (a pinning test fails if they do).

## 1.1.0 — 2026-10-17

Hardening release: no changes to any module's output semantics — one new
keyless data source, plus release-quality fixes to the seams that could drift
between versions.

**Added**

- **GitHub** social source, keyless through `api.github.com`: name, bio,
  location, contact email when published, follower/following counts, public
  repository count, account creation date, avatar and external links, plus
  the (most recently updated) public repositories as the account's post
  list. 60 requests/hour per IP unauthenticated; the adapter spends at most
  two per collection, validates the login locally before spending any,
  follows renames with a note instead of a silent identity swap, and puts
  the remaining budget on the result. Follower/following lists are walls,
  like every other keyless adapter. No browser, no login, no key — works on
  a bare install.

**Fixed**

- A social-tab click that arrived before (or without) the registry
  answering left the form on the previously selected platform — an
  Instagram config under the GitHub tab, including the browser-only
  options and burner-login row, and a hidden submit field that could
  still carry the old platform. A click now always wins the form
  immediately, and a platform this server's registry does not know (an
  older process since an upgrade, a broken adapter) is *named on the
  panel* instead of silently swapped — consistent with the rule that a
  partial state never renders as a confident one. A failed registry
  fetch no longer blanks the selection.

**Version attribution**
- Fixed version attribution across the tree. `pyproject.toml`,
  `spyglass_pro.version` and the vendored `instacloak` engine now all report
  **1.1.0** (they already agreed, by pinning test); the vendored
  `lens_extender` engine reports **1.0.0** instead of its stale upstream
  `1.0.0-dev` snapshot version.
- The dashboard's version is now visible in the UI — a version chip in the
  topbar, server-rendered so it cannot drift from `version.py`.
  (`/api/status` had always reported it; the HTML shell never showed it.)
- The overview's "API keys set" stat renders its initial `x/y` from the
  server (`len(_SETTINGS_SPEC)`) instead of a hard-coded `0/9` that would go
  stale the moment a tenth key spec is added.

**Drift-proofing (never fork a constant; fork no more)**

- `scripts/install_tools.py` imports blackbird's clone-location fallback
  list directly from `spyglass_osint.utils._BLACKBIRD_PATHS` instead of
  carrying its own hand-synced copy — the installer and the engines can no
  longer disagree about what "present" means. The regex-sync test is
  replaced by an identity test of the same list.
- The dashboard's per-module tool grid (`app.js`) is pinned by test against
  the server's `leg` vocabulary in `_degraded()` / `_TOOL_PROBES` — the two
  tables that drifted once before the release audit.

**Cross-OS (Windows)**

- `run.py` takes the user-scheme scripts directory from `sysconfig`'s
  per-platform scheme instead of hardcoding the POSIX
  `~userbase/bin` shape — a `pip install --user` engine was invisible on
  Windows, where it lands in `%APPDATA%\Python\<ver>\Scripts`. The PATH
  candidate list (venv, PIPX_BIN_DIR, pipx's per-OS defaults, blackbird's
  clone parent, user scheme) is pinned by a test that runs under its own
  platform on each CI job.
- `scripts/install_tools.py` is OS-aware: **exiftool** installs through
  winget (`OliverBetz.ExifTool`) with a chocolatey fallback; **dig** has
  no winget manifest (ISC ships BIND as a zip) and goes through choco's
  `bind-toolsonly`; **whois** comes from the Sysinternals suite;
  **torsocks** — which has no Windows port — answers with the honest
  alternative (`SPYGLASS_PROXY=socks5://127.0.0.1:9050`) instead of a
  broken install attempt. Every Windows failure names the package ID,
  the manager's own last output line and the exit code, and every
  Windows branch is driven offline by tests that pin the manager choice
  and rule out `_apt_install`/`brew` ever running there.

**CI / test infrastructure**

- Added a **Windows** test job (the README supports Windows; only its
  fallbacks were previously exercised by hand). The vendored engines'
  permission guards (`os.chmod`), filename handling and test suite were
  swept for POSIX-isms first; what remains Windows-specific is confined
  to guarded branches (`sys.platform == "win32"` checks in the config
  writers, per-platform PATH candidates).
- Added a **mypy** job — `mypy` was a dev extra that nobody ran; ten real
  type errors in the vendored engines and the social adapters are fixed.
- The node-based frontend tests now **fail** (not silently skip) when node
  is missing on a CI run, and the suite runs `node --check` on `app.js`
  first, so a syntax error in the dashboard JS is caught without the
  frontend test file even loading.

## 1.0.0 — 2026-10-04

Initial public release. One dashboard merging three engines
(Spyglass-OSINT, InstaCloak, Lens-Extender) behind one job pool, passive-only
by construction: every function that opened a connection to a target was
removed, and [AUDIT-2026-10.md](AUDIT-2026-10.md) inventories every one of
them.

Key elements from that audit (patched and verified by the dated verification
log at the end of the file):

- Debug-mode RCE off by default; loopback-only bind with an explicit warning
  on `0.0.0.0`; random per-process `SECRET_KEY`.
- Optional Bearer-token gate (`SPYGLASS_PRO_TOKEN`) for every `/api/*`
  route; non-loopback deployments require it.
- Proxy scheme whitelist ahead of the process environment; bounded job queue
  and scan timeout rather than unbounded threads.
- `safeHref()` guard against `javascript:` injection in result link tables.
- Full removed-active-scanning inventory tied to vendoring provenance
  (`NOTICE`), so upstream syncs are mechanical and nothing can quietly come
  back on.

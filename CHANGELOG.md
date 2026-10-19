# Changelog

Every entry is enforced by the offline suite (`python tests/run_tests.py`) —
the check counts quoted below are what the suite prints on a clean run.
Versions are read from `spyglass_pro/version.py` / `pyproject.toml`; those two
may not disagree (a pinning test fails if they do).

## 1.1.0 — 2026-10-17

Hardening release: three new keyless social sources, plus a security and
release-quality pass over the seams that could drift between versions. Every
change is safe by default — the new gate and headers only affect an
unauthenticated server, and no module loses a capability.

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
- **GitLab** social source, keyless through `gitlab.com/api/v4`, proving the
  keyless contract generalizes across forges. GitLab's unauthenticated user
  object is the honest *short* form — name, handle, avatar, instance URL,
  account state and a published email — so bio/location/website/joined are
  **not promised** in the panel's capability header and never fabricated;
  public projects carry the substance (name, description, stars, forks,
  last activity as the account's post list), with `post_count` taken from
  GitLab's own `X-Total` header rather than guessed, unset when GitLab
  doesn't answer it. Unknown handles answer with an empty list rather than
  a 404, so the "no such user" verdict is exact and cheap; handles are
  validated locally (dots/hyphens/underscores legal mid-name) before any
  budget is spent; locked/banned states are notes on the result. The
  keyless budget is GitLab's own number (500 requests/minute per IP,
  read from the instance's rate headers, never assumed).
- **Keybase** social source, keyless through
  `keybase.io/_/api/1.0/user/lookup.json`. Unlike every other source it
  returns the account's **cryptographically-proven identity proofs** — the
  Twitter, GitHub, Reddit, Hacker News, DNS and website accounts the user
  signed for with their Keybase key — which is proven cross-platform
  correlation rather than a guess from a shared handle. Only proofs in the
  proven state count as links; pending or revoked proofs are reported as a
  count and never folded into the verified set. The honest short form is
  stated up front: a profile (name, location, bio, avatar, creation time),
  the proof list and any on-file cryptocurrency addresses — but no
  follower/following counts and no post list, so those are neither promised
  nor fabricated. Unknown handles answer exactly (`{"them": [null]}`), and a
  name that fails Keybase's own 2–16 character rule is rejected locally
  before any request. No browser, no login, no key.
- **Optional forge tokens from the environment.** Both adapters honour a
  `GITHUB_TOKEN` / `GITLAB_TOKEN` environment variable when set and report
  the budget tier the *response* actually came back with ("keyless GitHub
  budget: 58/60 …" vs "GitHub budget (GITHUB_TOKEN authenticated): …").
  The never-there vault wording is gone from the exhausted-budget error:
  the message and the capability of the app now match.

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

- IPv6 targets now resolve. The `ip` module accepted
  `2001:4860:4860::8888` but `_resolve` was IPv4-only (`inet_aton`), so
  every IPv6 lookup died at "Could not resolve: …". Resolution asks the
  `ipaddress` module first and normalizes the address; validation uses the
  same literal check, so a stray colon (`gggg::1`) no longer passes as an
  address it never was.
- Phone and email validation matched the wrong shapes: `+1 415 555 0100`
  and `(415) 555-0100` were refused for containing a space or parens, while
  `-1234567` and `-a@b.com` were accepted — a leading dash could reach an
  engine's argv. Real phone separators are accepted, a leading `-` is
  refused, and an email local part must now start alphanumerically.
- README accuracy. The CLI-engine installer ships with a **source
  checkout**, not the wheel, so a PyPI install was told to run a file it
  does not have; the Quick Start now scopes it to a clone and directs pip
  users to install the engines directly. The "works on a bare install"
  claim was softened to name the tools Website and IP actually use (`dig`,
  `whois`, `curl`, `shodan`). The `README`/`SECURITY.md` encryption wording
  now says the entity index is encrypted too.

**Security (follow-up audit)**

- **Entity index now encrypted.** With `SPYGLASS_STORE_KEY` or
  `SPYGLASS_STORE_PASS` set, `runs.result_json` was Fernet ciphertext but
  the `entities` table — which holds the same domains, IPs, emails and
  orgs — was written in cleartext, so the store leaked exactly the target
  data it claimed to protect. Both are encrypted now and legacy plaintext
  rows still read. `SECURITY.md` and the README already made the promise;
  the code now keeps it.
- **Request-origin gate.** The default install is unauthenticated, so a
  DNS-rebinding page could read the whole API by pointing its own domain at
  `127.0.0.1` — the rebound request carries that domain as `Host` and looks
  same-origin to the attacker's page. While no token is set, requests are
  answered only under a loopback `Host` or one listed in the new
  `SPYGLASS_PRO_ALLOWED_HOSTS`; browser requests marked
  `Sec-Fetch-Site: cross-site`, or carrying a foreign `Origin`, are refused.
  A non-browser client sends neither header and is unaffected, and a token
  makes the host check unnecessary so hostname/proxy access keeps working.
- **Proxy credentials are no longer echoed.** `/api/status`, `/api/settings`
  and `/api/proxy` returned `http://user:pass@host:port` verbatim. They now
  return `http://••••@host:port`; an untouched Settings box (pre-filled with
  the mask) is left unchanged, and an edited mask is rejected with a clear
  message rather than stored as a literal credential.
- **Baseline response headers.** Every response now carries a
  `Content-Security-Policy` (strict `script-src 'self'`,
  `frame-ancestors 'none'`, remote avatars still allowed), plus
  `X-Frame-Options`, `X-Content-Type-Options` and `Referrer-Policy`; a
  stray unused jsDelivr preconnect was dropped from the shell.

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

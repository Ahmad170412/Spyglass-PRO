# Changelog

Every entry is enforced by the offline suite (`python tests/run_tests.py`) —
the check counts quoted below are what the suite prints on a clean run.
Versions are read from `spyglass_pro/version.py` / `pyproject.toml`; those two
may not disagree (a pinning test fails if they do).

## 1.6.2 — 2026-11-08

**Copy JSON works under the dashboard's CSP, and the README shows 1.6.**

- **Copy JSON was blocked by the dashboard's own CSP.** The result card
  built its button with an inline `onclick`, which `script-src 'self'`
  refuses before it runs, so the button was dead on every result. It is
  now one delegated `data-copy` listener, and a UI-contract test fails if
  an inline event handler reappears.
- **The README now shows the current build.** The old hero screenshot
  still advertised the removed IP module, Enrichment and three platforms;
  it is replaced with current 1.6 captures of the tracked-target dashboard,
  the person card, Targets and the Cases diff. The gallery is labelled as
  fictional example data.

`tests/run_tests.py` — **719 checks, 0 failed** (was 718).

## 1.6.0 — 2026-10-30

**History moves to a vertical rail; Instagram checks keep their media.**

- **The check history is a right-hand sticky rail**, newest check at the
  top, oldest (the baseline) at the bottom. Each card is a button: clicking
  it rewinds the main column — counts, delta labels, the diff verdict, new
  posts — to that check. No refetch and no second diff implementation: the
  target detail now carries a per-snapshot `diff` computed by
  `social/diff.py`, exactly the verdict the check produced. "Today" means
  the latest check, labelled with its real date and time.
- **The main column fills the space the rail frees.** The dashboard is a
  two-column grid (content + 300px rail, stacking below 1080px) instead of
  a 720px centered column; the identity band, options and panels widen with
  it.
- **Instagram media, per check.** Stories and each post's downloaded files
  are stored in the snapshot beside their timestamps, and
  `GET /api/social/media/<target>` serves only files referenced by that
  target's snapshots and sitting under a configured output root. The Media
  panel follows the selected check: that day's stories and post images, in
  an in-page lightbox. Three states stay distinct — not captured (old
  snapshot), capture refused/unavailable (no burner login), and captured
  but empty (no active stories). Text is honest about all three.
- **Stories download with the media flag**, not only in deep mode, so a
  normal logged-in check keeps the tray it saw.
- **The dashboard loads exactly once.** A botched edit had left two full
  copies of `index.html` in the file — the second one after the first
  `</html>` — so `app.js` executed twice: every handler was bound twice
  (one submit queued the scan twice, page load fired API calls 2–4×), 38
  ids were duplicated, and the newer markup (plain panel headings, the
  two Settings hint lines, `new-password` autofill) sat dead in the
  unreachable copy. The stale tail is removed: one document, one script
  tag, unique ids, and the newer markup now renders. Pinned by the new
  `TemplateStructureTest` so the suite reads the template from now on.
- **Nothing renders below 10px.** The rail's `latest` tag (8.5px) and
  `newest first` (9.5px) led nine more badges and labels under the
  floor; every `font-size` in the stylesheet is now ≥10px, pinned by
  `StyleFloorTest`.
- **Narrow panes keep the full content width.** Below 768px the sidebar
  becomes a horizontal strip — group labels hidden, items scrolling
  sideways — instead of standing beside the content and crushing it to
  a ~90px column, so split preview panes and snapped half-windows stay
  readable.

**Targets and CHECK AGAIN: social tabs become tracked dashboards.** The
free-form social run is gone; a handle is added once on the new **Targets**
panel and each platform tab becomes *that target's* dashboard. GREENWICH's
lessons drive the shape (see `mockups/social-changes-mockup.html`, the
approved design source):

- **`spyglass_pro.social.tracking`** — durable targets and per-check
  snapshots in the same `spyglass.db` as the case store (one key, one path,
  same Fernet encryption; deleting the store deletes everything, once).
  The last 20 checks per target are retained; the *baseline* lives on the
  target row so it survives pruning. A failed run updates bookkeeping only
  and never writes a snapshot — a network blip cannot overwrite a good
  baseline or pollute the diff chain. Handles normalize once (stripped `@`,
  lowercased), so `@Dawn` and `dawn` are one target, not two.
- **`spyglass_pro.social.diff`** — the pure check-to-check diff engine.
  Posts are additions-only keyed by native id (a bounded window cannot
  prove deletion); each list side is gated on its own completeness flag
  (the collector proved enumeration finished, not the lagging counter);
  counts compare only when both sides saw them; a wall that appeared is a
  first-class change. Refusals come back as `{ok: false, error}` and render
  as refusals — "could not compare" and "nothing changed" never look the
  same. `social/lists.py` is the walker behind those flags: one order for
  every view, the counter-lag rule enforced at collection time.
- **`POST /api/social/targets/<id>/check` replaces `/api/social/run`**
  (the old route is a 404): collect → diff against the last *successful*
  check → record, in the isolated `SOCIAL_POOL`, with the same
  blocking/async transport as every other run route. `GET
  /api/social/targets/<id>` carries `history` and `last_diff`, recomputed
  with the shared engine on every load, so the dashboard shows exactly the
  verdict the check produced — never a second, client-side diff.
- **The dashboard**: identity band with last-check and baseline stamps,
  stat cards with deltas against the last check (a count the platform did
  not report renders no number), per-list diff panels with completeness
  footers and refusal notes, new posts, and a horizontal history rail read
  oldest → newest (one order everywhere). No target yet is a blank state
  that links to Targets; an unreachable store resolves to a blank state
  that says so — nothing is guessed while the store is down.
- **The burner account moved to Settings** — it is account config, not
  target config. It stays in the browser and rides a check payload only
  for platforms whose registry entry declares a login; keyless tabs never
  receive it and never offer the browser-only options (headless, deep,
  media) that do not exist for them.
- **GREENWICH theme** across the app: flat black, one hairline, sharp
  corners, uppercase kickers, label-above-number stats, red reserved for
  change and severity.
- **Diff honesty pass — a re-signed CDN URL is not a profile change.**
  Avatar identity is now scheme + host + path, so Instagram's per-fetch
  `oh=`/`oe=` query tokens can no longer manufacture an "Avatar changed"
  row on every check; a real swap still shows, because the photo id lives
  in the path. The rule is scoped to `avatar_url` — a website's query is
  content and still diffs. Link and image field changes render as the
  full href behind a short host + path label, so a change is verifiable
  by clicking rather than by copying a truncated string (which is not a
  URL and gets rejected wherever it is pasted).
- **Dashboard breathing room.** The identity band and last-check line
  share the 720px card column, so the header never hangs left of the
  cards below it; the handle and the action button never break mid-word
  (in panes ≤760px the button drops to its own full-width row and
  options fall to a single column); the options row is an aligned grid
  instead of a centered flex line with an orphaned last item; diff notes
  wrap long URLs instead of scraping across the panel.
- **A failed post fetch can no longer manufacture 40 "new posts."**
  The posts diff now requires the previous side's window to prove
  newness: an empty window beside a nonzero `post_count` (or an unread
  count) means the feed fetch failed — the adapter already notes it —
  so additions are refused with the reason, which renders as a refusal
  box rather than as "nothing changed". A baseline that truly saw zero
  posts (count == 0) still proves additions, so a genuinely new account
  reporting its first posts remains a real finding. Found by an
  end-to-end check of a Bluesky target whose feed call failed once.
- **Panel descriptions align with their form cards.** `panel-desc` is
  560px to match `module-form`: two centered blocks 10px apart read as
  a mistake, not as hierarchy. Verified with a fresh-store instance:
  every panel, empty and populated, at 1280px and 760px — zero
  overflow, clipping, text overlap, sub-9.5px text or undersized hit
  targets, clean console, all API 200s.

**The buried IP/web OSINT code is deleted, not dormant.** 1.5.0 unexposed
the IP module, the heavy website phases and Lens-Extender and pinned the
boundary around them — but they still sat in the tree, importable and
tested. They are gone now:

- **`spyglass_osint.ip`** — the whole module, its dispatch handler, its
  target validation, its summary branch, its report renderer and its fact
  extractor.
- **Lens-Extender's engine** — `osint`, `analyzer`, `app`, `cli`, `config`,
  `report` and `__main__`, plus `runner.run_lens`, the `/api/lens/run`
  endpoint and the engine's row in `/api/status`. What survives is
  `lens_extender.store`, trimmed to the table handle the merge layer needs:
  legacy `lens_*` rows still list and delete, but its scan writer went with
  the engine, so nothing in this build can create a Lens run.
- **The heavy website phases** — Shodan/ports with its reverse-DNS sweep,
  the aggregated subdomain sweep (HackerTarget / CertSpotter / Wayback) and
  the helpers that only fed them (`_reverse_dns`, `_is_ipv4`/`_is_ipv6`, the
  `_ips`/`_wild` plumbing), plus the `_SHODAN` tool detection nothing reads.
- **The dormant vocabulary** — `scope.DORMANT_*`, `dormant_error()` and the
  HTTP refusal branch that carried them. `EXPOSED_MODULES` is now the whole
  vocabulary and the boundary still refuses anything outside it;
  `tests/test_scope.py` fails if a removed file, function or endpoint
  reappears.

**Kept on purpose** — the light website surface (`WEBSITE_LIGHT`: registrant,
WHOIS, DNS, e-mail security, wildcard, CT), every exposed module, and the
case-store compatibility that keeps already-stored data honest: stored `ip`
runs still diff, timeline and export, legacy `lens_*` rows still list and
delete, and the vault still imports `~/.lens-extender/config.json` once.

`tests/run_tests.py` — **718 checks, 0 failed** (was 627).

## 1.5.0 — 2026-10-20

The pivot release: Spyglass-Pro stops being an *infrastructure* product and
becomes a **HUMINT** one. The IP module, the heavy website phases and
Lens-Extender are no longer part of the product surface, and the build gains
what replaces them — identity resolution, and a light website recon that
touches only third parties.

**Version numbering.** The public history is `1.0.0 → 1.1.0 → 1.5.0`.
`1.2`, `1.3` and `1.4` were internal builds of this work: they were never
published to PyPI and never had a release, so the public history skips them
rather than pretending they exist. `1.5.0` rather than `2.0.0` because the
project is weeks old, not because the changes are small — they are breaking
(see below) — and `2.0` is reserved for a stable HUMINT API. `1.1.0` is the
last public release that contains the IP/Lens infrastructure.

**Breaking changes**

- **The IP module and Lens-Extender are unexposed.** No dashboard panel and
  no API endpoint can reach them any more: `GET /api/spyglass/run?module=ip`
  and `GET /api/lens/run` both answer `400` with a message that names the
  reason. The code is **not deleted** — it stays in the tree, importable and
  tested, because a sibling tool consumes it. The exposure boundary is
  enforced, not documented: `app.py` now refuses any module that is neither
  exposed nor explicitly dormant, and a test pins the handler map to
  `exposed ∪ dormant` so a new engine cannot become reachable by accident.
- **Website recon is light, passive and owner-scoped.** The Website panel
  does owner/registrant, WHOIS, basic DNS, e-mail security records (SPF /
  DMARC / DKIM / CAA), wildcard-DNS detection and Certificate Transparency.
  Shodan, port checks, HTTP header collection, the aggregated subdomain
  sweep and Wayback history are dormant. The panel accepts **a domain or an
  `http(s)` URL only** — a direct IP address is refused. A pasted URL is
  normalized to its host, so `https://example.com/page` and `example.com`
  are one case, not two.
- **A website is context, not an identity anchor.** A domain you type in
  never becomes "who this person is". It stays under Identity as context;
  IPs derived from it passively remain investigation entities.
- **Settings offers two keys, not nine.** Only IntelX and HIBP — the two
  an exposed module actually reads. The dormant infrastructure keys (Shodan,
  VirusTotal, AbuseIPDB, Censys, GreyNoise, NVD) are gone from the vault UI
  and stay in the old config file untouched.
- **The API-key vault moved.** Settings used to be stored in the vendored
  Lens engine's config file (`~/.lens-extender/config.json`). The vault now
  owns `~/.spyglass/vault.json` (0600 on POSIX). On first run it imports the
  live keys from the old file **once** and leaves that file exactly as it
  was — so the sibling tool keeps working, and cutting Lens out of this
  tree in a later version can no longer take Settings storage with it.

**Added**

- **Identity resolution** (`spyglass.person/1`) — Full Investigation now
  resolves its inputs into a *person model* instead of a bag of entities:
  anchors, attributes, accounts, breaches, links, conflicts and context, in
  seven layers. Shared handles and e-mail local-part matches are recorded as
  **possible**, never as merges: a shared handle is not proof, and the build
  says so. Links carry `high` / `medium` / `possible`; the overall verdict
  carries `high` / `medium` / `unconfirmed`. One value per field, but the
  model is list-ready. The layer is **additive**: no new query type, no new
  endpoint, no new store path — it rides on the existing Full Investigation
  run, and stored runs from older versions render exactly as they did.
- **A results UI that reads like a report.** Each result card leads with a
  compact person grid, a three-column accounts table, compact links and
  conflicts, and the one-line summary under the card header. `Details`,
  `Run log (N)` and `Raw JSON` are collapsed drawers instead of walls of
  text. The correlator's detail moved into `Details` as well.
- **A themed delete dialog.** Deleting a stored case uses an in-app
  `<dialog>` — cancel, Esc, backdrop click and confirm all behave — instead
  of `window.confirm`.

**Fixed**

- **Website targets reached the engine unnormalized.** The case label used
  the normalized host while the engine received the pasted input, so a
  scheme-less path (`example.com/about`) passed validation and then produced
  an empty WHOIS/DNS/CT report instead of the site's records. The engine gets
  the host now.
- **`/api/cases` could take the whole Cases panel down.** The store
  connection sat outside the `try`, so a read-only home or a corrupt
  database raised past the endpoint and returned HTML where the dashboard
  expected JSON. Both stores degrade to an empty list now.
- **Legacy Lens case rows promised a timeline that does not exist here.**
  They were clickable but had no diff/timeline/profile in this build, so a
  click answered "no stored runs" for a row that was right there. Those rows
  are marked read-only and say so; they can still be deleted.
- **The source distribution shipped a working draft.** `MANIFEST.in` does
  not read `.gitignore`, so `python -m build` copied the ignored
  `docs/PLAN-*.md` into the sdist. It is excluded now, and the exclusion is
  verified against a real build.
- **Dead heavy-website helpers were cut from the exposed module**:
  `_SUB_LIST`, `_http_status`, `_http_bytes`, `_parse_headers_block` and
  `_NoRedirect` had no callers anywhere in the tree.
- **The optional-engine installer stopped shipping a Shodan CLI** that no
  exposed module uses.

**Kept on purpose** — the dormant IP/Lens code, the heavy website phases
and the `lens_extender` package stay in the tree, importable and tested,
for the sibling tool. A later release removes them permanently; this one
only stops exposing them.

`tests/run_tests.py` — **627 checks, 0 failed** (was 612).

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

# Spyglass-Pro

![Dashboard overview](docs/screenshots/dashboard-overview.png)

Unified OSINT dashboard that wires three recon engines into one platform:

| Engine | Purpose |
| --- | --- |
| **Spyglass-OSINT** | Email / username / phone / website / IP / dark-web / OPSEC / metadata recon |
| **InstaCloak** | Instagram profile collection (posts, contacts, followers, tags) |
| **Lens-Extender** | Long-range IP/domain recon — passive-first, optional active nmap |

The **Investigation** view runs the engines in parallel and correlates
entities across sources (shared emails, IPs, domains, usernames).

## Install

```bash
git clone <spyglass-pro-repo> && cd Spyglass-Pro
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
```

Optional CLI engines (sherlock, maigret, holehe, user-scanner, ignorant,
nmap) are discovered on `PATH` when installed; every module degrades
gracefully when one is missing.

## Run

```bash
python run.py            # or: python -m spyglass_pro  /  spyglass-pro
```

Then open <http://127.0.0.1:5000>.

## Test

```bash
.venv/bin/python tests/run_tests.py
```

239 offline checks — the three engines' own suites plus the merge layer
(API surface, auth gate, proxy validation, job pool, case queries). No
network and no browser required.

## Configuration

All settings are environment variables (CLI flags exist for the basics —
see `spyglass-pro --help`):

| Variable | Default | Purpose |
| --- | --- | --- |
| `SPYGLASS_PRO_HOST` | `127.0.0.1` | Bind address |
| `SPYGLASS_PRO_PORT` | `5000` | Port |
| `SPYGLASS_PRO_TOKEN` | — | Require this Bearer token on every `/api/*` route |
| `SPYGLASS_PRO_SECRET` | random per process | Flask `SECRET_KEY` |
| `SPYGLASS_PRO_DEBUG` | `0` | Werkzeug debug mode (**RCE console — never enable on a reachable host**) |
| `SPYGLASS_PRO_MAX_QUEUE` | `16` | Max pending scan jobs before rejecting |
| `SPYGLASS_PRO_JOB_TIMEOUT` | `900` | Seconds a request waits for a job |

## Security notes

- Binds loopback-only by default; set `SPYGLASS_PRO_TOKEN` before binding
  any other address (the server warns at startup if you don't).
- Debug mode is off by default.
- Proxy URLs are validated (http/https/socks schemes only) before they
  reach the environment shared by every subprocess.
- Scan jobs are queue-capped and time-bounded; results are HTML-escaped
  and links are restricted to http/https/mailto.

## Responsible use

OSINT tools are dual-use. Only scan systems and accounts you own or have
explicit permission to test. Instagram collection via InstaCloak may
violate the platform's terms of service; active (nmap) scanning is
regulated in some jurisdictions. You are responsible for compliance with
applicable laws.

## Project structure

```
run.py                  dev entry point
tests/                  239 offline checks (run_tests.py)
spyglass_pro/
  app.py                Flask routes + auth gate + proxy validation
  runner.py             job pool (queue cap, timeouts), engine dispatch
  cli.py                `spyglass-pro` console entry point
  templates/ static/    dashboard UI
  modules/              vendored engines (see NOTICE)
```

## Cases

Every scan can be stored (`Store in Cases`). Stored runs keep a full result
snapshot plus an entity index (domains, IPs, emails, phones, orgs, onions,
breaches), which is what the **Stored Cases** panel reads:

- **Diff last two runs** — entities that appeared or disappeared since the
  previous run of the same target and query type.
- **Timeline** — every stored run of a target, oldest first.
- **Export dossier** — the latest run per query type merged into one JSON
  profile.

Data at rest is encrypted with Fernet when `SPYGLASS_STORE_KEY` (base64
32-byte key) or `SPYGLASS_STORE_PASS` is set; otherwise it is stored in
plaintext. The store location follows `SPYGLASS_HOME` (default
`~/.spyglass`). JSON/CSV/report artifacts from a scan land in the working
directory of the run.

## License

MIT — see [LICENSE](LICENSE) and [NOTICE](NOTICE) for the bundled
engines' copyrights.

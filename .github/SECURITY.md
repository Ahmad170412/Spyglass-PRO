# Security Policy

## Scope

Spyglass-Pro is a **passive-only** OSINT dashboard. It resolves DNS, reads
Certificate Transparency logs and WHOIS registries, and queries third-party
APIs. It never opens a connection to a target — no port scan, no directory
brute force, no HTTP probe of a discovered host, no zone transfer, not even
a fetch of a target's homepage. See `AUDIT-2026-10.md` for what that means
in practice and for the code that was removed to guarantee it.

Two things do reach out over the network on your behalf, and both are worth
knowing about:

- **The social harness** drives a real browser against a real platform
  (Instagram), using a burner session you supply. It never touches a
  target's own infrastructure, but it does run automated collection against
  a third party's service.
- **Passive queries** go to third-party APIs, so the *target* of an
  investigation is disclosed to those services, and your source IP is
  visible to all of them. Use a proxy (`SPYGLASS_PROXY` or the dashboard's
  proxy box) if that matters to you.

## Reporting a vulnerability

Report privately via **GitHub Security Advisories** on this repository
("Security" → "Report a vulnerability"). Please do not open a public issue
for a vulnerability.

Include: what you ran, what you expected, what happened instead, and the
file/line if you have it. A working proof-of-concept against infrastructure
you own is ideal.

I'll aim to acknowledge within a few days. Fixes land in a branch and are
credited in the advisory unless you'd rather stay anonymous.

## Things that are not vulnerabilities

- **Missing coverage.** A recon leg that silently returns nothing is a
  product limitation, not a breach — the UI is meant to disclose which legs
  cannot run (`degraded` / `missing_tools` in `/api/status`).
- **The tool finding something.** It is a recon tool; output about a target
  is the intended function.
- **Platform terms of service.** Automated collection may violate
  Instagram's or another platform's terms. That is a risk you accept by
  running the social module, not a bug in this project.
- **Running the Flask dev server in production.** It is a development
  server. Put gunicorn or uwsgi in front of it for a real deployment.

## Deployment notes

- Binds `127.0.0.1` by default and debug mode is off. Set
  `SPYGLASS_PRO_TOKEN` before binding any other address; the server warns
  at startup if you don't.
- `SPYGLASS_PRO_DEBUG=1` enables Werkzeug's interactive traceback console,
  which is arbitrary code execution. Never enable it on a reachable host.
- Cases are encrypted at rest when `SPYGLASS_STORE_KEY` (base64 32-byte
  key) or `SPYGLASS_STORE_PASS` is set; otherwise they are plaintext under
  `SPYGLASS_HOME` (default `~/.spyglass`).
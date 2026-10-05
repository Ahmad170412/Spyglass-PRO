# Contributing to Spyglass-Pro

## The one rule that overrides everything else

**Spyglass-Pro is passive-only. Never open a connection to a target.**

Every query goes to a third party — DNS resolvers, Certificate Transparency
logs, WHOIS registries, InternetDB, RDAP, RIPEstat, Wayback, crt.sh,
CertSpotter, HackerTarget, breach databases. Spyglass-Pro itself never
connects to the thing being investigated.

That means no port scan, no directory brute force, no HTTP probe of a
discovered host, no zone-transfer attempt, and not even a fetch of a target's
homepage. Ordinary DNS record lookups (A, MX, NS, TXT, SPF, DMARC, CNAME) are
fine — every OSINT tool treats them as passive, and no useful host recon
exists without them.

Active collection lives in a separate project. If you find yourself wanting to
add a probe, that is the signal to stop, not a feature request. See
[AUDIT-2026-10.md](AUDIT-2026-10.md#active-scanning-removed) for what was
removed and why, so you know the line was drawn deliberately.

A PR that reintroduces any form of target contact will be rejected regardless
of how useful it looks.

## Setup

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
python scripts/install_tools.py --check    # what recon engines are missing
```

## Run the tests

```bash
.venv/bin/python tests/run_tests.py
```

The suite is offline — no network, no browser — and finishes in about a
second. **It must pass before you open a PR.** It runs the three vendored
engine suites plus the merge layer (API surface, auth gate, proxy validation,
job pool, case queries, target validation).

New behaviour needs a test that fails without your change. The project has
been consistent about this: fixes that could have regressed silently are
pinned by a check.

## Adding a social platform

The social harness is registry-driven. Instagram is the only adapter today; a
new one is a new module plus a `@register` line.

```python
# spyglass_pro/social/platforms/<name>.py
from .. import registry
from ..schema import set_fields, add_wall

def collect(page, cfg, handle, result): ...
def normalize(raw, result): ...          # pure — unit-test it offline

registry.register(registry.Platform(
    key="tiktok", label="TikTok", url="https://tiktok.com/@{handle}",
    capabilities=("profile", "bio", "follower_count"),
    login="none", collect=collect,
))
```

Then list it in `registry.load_all()`. It appears in the UI, the report and the
API with no other changes.

Two rules that are not negotiable:

- **`normalize()` must be pure.** It takes raw collected data and returns
  normalized fields — no network, no browser. That is what makes it testable
  offline, and it is the only reason the suite stays offline.
- **Be honest about what you did not get.** A list that needs a login is
  reported as *walled with a reason*, never as an empty list. A partially
  retrieved list is labelled partial. A result that looks complete but is
  silently incomplete is a bug, and it is the specific failure mode this
  project cares most about.

If you add a field to the schema, the dashboard's JS field table is pinned to
`schema.PROFILE_FIELDS` by a test — so a divergence fails the suite instead of
rendering a blank cell. That pin exists because it already caught that class of
bug once.

## The vendored engines

`spyglass_pro/modules/` holds three engines — `spyglass_osint`, `instacloak`,
`lens_extender` — folded in from standalone projects. They sit behind a
directory boundary on purpose:

- **Do not refactor them into the merge layer.** They are kept whole so the next
  sync from upstream is mechanical.
- **Merge-layer code imports them; they do not import the merge layer.**
- Their formatting follows this repo's `ruff` config, so line wrapping and
  import order differ from upstream. The logic does not.
- Some files carry fixes that exist *only* here. `AUDIT-2026-10.md` lists them
  under "Merge provenance" — check before re-syncing, or you will revert a bug
  fix.

## House style

- `ruff check .` must pass (line length 120, isort ordering).
- Comments explain **why**, not what. The existing code is unusually good on
  this — match it. A comment that restates the code is noise; a comment that
  records the reason a decision was made is the most valuable thing in the
  file.
- Prefer editing an existing file over creating a new one.
- `mypy` is configured but not yet clean; it is not in CI.

## Honest reporting is a feature

The single most repeated theme in this codebase's history is *not losing
information silently*. Passive sources lost to one failed request, a phone
number correlated to an unrelated country, a documented source that was never
implemented, a burner login that silently failed while the operator believed it
was on. Each was a bug.

So when you change behaviour, ask: does this ever make a partial result look
like a complete one? If so, it is wrong, regardless of what the code looks
like.
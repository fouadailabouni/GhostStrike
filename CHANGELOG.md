# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org/): `MAJOR.MINOR.PATCH`.

No tagged releases yet — this file starts tracking from the current
pre-release development on `main`. The first tagged release should be
`3.0.0`, matching the version already carried in `CyberToolkit/ghoststrike.py`'s
`APP_VERSION` and the project's `[PHANTOM]` codename.

## [Unreleased]

### Added
- Engagement OS foundation: attack graph builder, cross-run finding
  deduplication, an MCP server exposing engagement data read-only, and
  Report Studio (executive/technical/developer variants; HTML/JSON/SARIF/
  Markdown export).
- Purple Mode: maps executed techniques (from real recorded findings'
  MITRE tags) to real detection evidence via a pluggable backend, with an
  honest `N/A` for anything it can't verify and a working local-host-log
  backend.
- `install.sh`: environment detection, CORE/RECOMMENDED/SPECIALIZED
  dependency tiers, PEP 668 (`externally-managed-environment`) handling.
- `system_doctor.sh`: a single health-check command covering system,
  tools, GhostStrike configuration, and AI Co-Pilot readiness.
- Local-first AI: a `local` model backend for any OpenAI-API-compatible
  server (Ollama, LM Studio), plus `GHOSTSTRIKE_OFFLINE` to hard-refuse
  cloud AI backends when set.
- Module SDK: `tools/gs_module_init.py` (scaffolding) and
  `tools/gs_module_validate.py` (a real static checker — manifest/code
  trust-level drift, missing policy gate, unsafe `eval`/`bash -c`
  patterns), plus `schemas/module_manifest.schema.json`.
- A "Python Quality" CI job (syntax, Ruff, Bandit, pytest) — informational
  only for now given the size of the pre-existing findings backlog; see
  `docs/TESTING.md`.
- Adversarial tests against `lib/scope_check.py` documenting two real,
  unfixed gaps: no IDNA/punycode domain-equivalence checking, and wildcard
  exclusion entries (`*.internal.example.com`) silently matching nothing.
- A restructured `/docs` folder (install, quickstart, architecture, safety
  model, AI Co-Pilot, module system, testing, licensing, roadmap),
  `CONTRIBUTING.md`, and GitHub issue templates.
- The credential vault (`lib/vault.sh`) now uses real authenticated
  encryption (`lib/vault_crypto.py`: PBKDF2-HMAC-SHA256 → AES-256-GCM),
  replacing a prior implementation that shelled out to plain AES-256-CBC
  despite already documenting itself as GCM.

### Fixed
- Numerous CI-flakiness root causes in individual modules: missing
  `-xdev` on filesystem scans, `set -e` traps from bare `[ cond ] && cmd`
  statements, `--dry-run`/`GS_DRY_RUN` flags accepted but never wired to
  skip real work, and cloud-CLI (`az`/`gcloud`) cold-start latency in the
  module smoke test.

### Known gaps (tracked, not yet fixed)
- Scope-check IDNA/punycode equivalence and wildcard exclusion support
  (see adversarial tests above).
- Ruff/Bandit findings from the first-ever run of each tool are not yet
  triaged; both currently run informationally in CI.
- `CyberToolkit/engagement_repository.py`'s `update_finding()` builds an
  `UPDATE` statement with column names interpolated via f-string (values
  are correctly parameterized) — needs confirmation that `fields` keys can
  never originate from untrusted input before this can be marked safe.
# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org/): `MAJOR.MINOR.PATCH`.

## [3.0.0] — 2026-09-01 — PHANTOM

First tagged release, matching the version already carried in
`CyberToolkit/ghoststrike.py`'s `APP_VERSION`.

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
- Fail-closed policy engine: `gs_policy_check_trust`'s fallback (used only
  when `policy.yaml` is missing/unreadable) now blocks every trust level
  outside `lab`, instead of silently allowing `SAFE_ENUM`/`VALIDATION`
  through with no policy file present.
- AI redaction gap: extracted the fail-closed secret-redaction logic into
  a shared `ai_engine/redaction.py` and wired it into `js_analyzer.py`,
  which previously shipped extracted JS secrets to the model unredacted.
- Shell-injection hardening across `osint_orchestrator.py`, `code_runner.py`,
  `network_capture.py`, and `shell_executor.py` — converted `shell=True` +
  f-string command construction to list-argv or `shlex.quote()`-wrapped
  values.
- `engagement_repository.py`'s `update_finding()` now enforces a column
  allow-list on its SQLite branch, closing a SQL-injection-shaped gap where
  `fields` keys were interpolated directly into an `UPDATE` statement.
- `gs_finding_new()` was silently stripping the schema-required `impact`/
  `remediation` fields from every new finding (a stale hardcoded field
  list, with the validation failure swallowed by a trailing `|| true`).
- Nikto import/dedup: distinct findings sharing a URI (missing CSP, missing
  HSTS, outdated Apache, ...) were producing identical titles and getting
  merged as duplicates; titles now embed the item's own description and
  dedup excludes purely-numeric tokens (IP octets, ports) from
  title-similarity comparisons.
- Least-privilege: `find_bash_invocation()` no longer forces `sudo` for
  callers that never need root (finding-metadata writes, SARIF export).
- CRLF corruption in `lib/reproducibility.sh` that broke it outright on
  real Linux, undetected until this release's test pass actually exercised
  the script.

### Known gaps (tracked, not yet fixed)
- Scope-check IDNA/punycode equivalence and wildcard exclusion support
  (see adversarial tests above).
- Ruff/Bandit findings from the first-ever run of each tool are not yet
  triaged; both currently run informationally in CI.
- GUI has no control to select the local/Ollama AI backend yet — set the
  `GHOSTSTRIKE_AI_BACKEND=local` environment variable before launch as a
  workaround.
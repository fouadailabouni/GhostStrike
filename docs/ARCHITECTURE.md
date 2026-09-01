# Architecture

## Directory layout

```
GhostStrike/
├── CyberToolkit/                    # GUI + AI Co-Pilot (Python)
│   ├── ghoststrike.py               # Main GUI entry point
│   ├── cyber_toolkit.py             # Alternate launcher
│   ├── script_metadata.py           # Per-module metadata the GUI reads
│   ├── engagements.json             # Local engagement registry (gitignored)
│   ├── ai_engine/
│   │   ├── agents/                  # 11 persona agents (see AI_COPILOT.md)
│   │   ├── mcp_server/              # Read-only MCP server over engagement data
│   │   └── tools/                   # module_runner.py and friends
│   ├── report_studio/               # Report generation (see below)
│   └── assets/                      # Icons, branding
│
└── bash_scripts_for_pentest/        # The module framework
    ├── lib/                         # Shared infrastructure (see below)
    ├── schemas/finding.schema.json  # The finding shape every module writes to
    ├── policy.yaml                  # Policy engine configuration
    ├── scope.yml.template           # Engagement scope template
    ├── repro_runner.sh              # Reproducibility wrapper for any module
    ├── benchmarks/                  # Benchmark validation mode
    ├── metrics/                     # Reproducibility + attack-graph output
    ├── runs/                        # Engagement run index (gitignored)
    ├── 00-Framework-Core/ … 21-Bypass-Techniques/   # 22 module categories
    └── tests/                       # framework_test.bats, test_helper.bash
```

Root-level `tests/` (outside `bash_scripts_for_pentest/`) holds the two things
CI actually runs: `test_framework.sh` (lib unit tests) and
`module_smoke_test.sh` (per-module syntax/no-args/`--help` sanity — see
[TESTING.md](TESTING.md)).

## `lib/` — the shared foundation every module sources

Every module starts with the same line: source `lib/common.sh`, then call
`gs_policy_gate` once argument parsing is done. `common.sh` auto-sources
`policy_engine.sh`, `evidence.sh`, `finding_ontology.sh`, and
`reproducibility.sh` — a module never has to source those explicitly.

| File | Purpose |
|---|---|
| `common.sh` | Environment/logging/exec-wrapper foundation; auto-sources the four files below |
| `policy_engine.sh` | Implements `gs_policy_gate` — the pre-execution authorization check every module calls |
| `policy_query.py` | Reads `policy.yaml` at runtime so policy changes don't require touching code |
| `scope_check.py` | Real CIDR/domain-aware scope matching (not substring matching) |
| `evidence.sh` | Per-session evidence directory, SHA-256 hashing, MITRE tagging, signed manifest |
| `finding_ontology.sh` | Normalizes findings against `schemas/finding.schema.json`; SARIF/JSON export |
| `finding_dedup.sh` / `finding_dedup.py` | Cross-run finding deduplication (CVE overlap, host+port+title similarity, MITRE+time overlap); never deletes — superseded findings are marked, not removed |
| `reproducibility.sh` | 0–100 reproducibility scoring used by `repro_runner.sh` |
| `trust_registry.sh` | Source of truth for module trust levels |
| `vault.sh` | Credential storage for modules and the AI Co-Pilot |
| `session_manager.sh` | Persistent Metasploit RPC sessions across separate module invocations |
| `msf_rpc_client.py` | `pymetasploit3` wrapper used by `session_manager.sh` |
| `engagement.sh` / `engagement_query.py` | Read-only query layer over a run's findings, evidence, and reproducibility data — the shared foundation for the attack graph, dedup engine, and MCP server |
| `attack_graph_builder.py` | Builds a host → service → finding attack graph purely from `engagement_query.py` output; renders a self-contained HTML page (no server, no CDN) |
| `purple_mode.sh` / `purple_mode.py` | Maps executed techniques (from findings' `mitre_attack.technique_id`) to real detection evidence via a pluggable backend — see below |

## Purple Mode (`lib/purple_mode.py`, `17-Monitoring-Detection/purple_mode_validator.sh`)

Answers "did anything actually detect what we just did" from real recorded
findings, not a simulation. For every technique with at least one finding in
scope, a **backend** checks for real evidence it was logged and/or alerted
on, and the module reports Executed / Logged / Alerted per technique plus an
overall coverage percentage.

- **`local` backend (implemented)**: greps real host logs (`journalctl`,
  `/var/log/auth.log`, `/var/log/syslog`, `fail2ban.log`) for
  technique-correlated patterns within a time window around the finding.
  Its scope is deliberately limited and stated as such in the module's own
  docstring: it checks the logs of whatever host the check runs *on* — a
  meaningful signal if that's the system you attacked, not a substitute for
  checking a real target's SIEM.
- **`wazuh` / `elastic` / `splunk` / `sentinel` / `security_onion` backends**:
  not implemented. Selecting one raises `BackendNotImplemented` and reports
  clearly per-technique rather than fabricating a result — see the `Backend`
  interface in `purple_mode.py` for how to add a real one.
- A technique with no backend rule at all is reported `N/A`, never coerced
  to a false "not detected" — the coverage percentage excludes `N/A`
  entries from its denominator rather than silently punishing them.

## AI Co-Pilot (`CyberToolkit/ai_engine/`)

11 persona agents (Red Team, Blue Team, Web Pentest, Bug Bounty, DFIR,
Reverse Engineering, WiFi, CTF, Purple Team, NLP Router, Output Analyst) share
a common base class and drive modules through `ai_engine/tools/module_runner.py`.
Every module call an agent makes goes through the identical `gs_policy_gate`
check a manual run does — there is no separate, more permissive code path for
AI-driven execution. See [AI_COPILOT.md](AI_COPILOT.md) for the full list and
the redaction model.

## MCP server (`CyberToolkit/ai_engine/mcp_server/`)

A local, stdio-only MCP server (no network transport) exposing read-only
tools over engagement data: `list_engagements`, `get_engagement`,
`list_findings`, `get_finding`, `get_attack_graph`, `get_repro_score`. Write
tools are deliberately excluded from this first pass.

## Report Studio (`CyberToolkit/report_studio/`)

Generates three report variants — executive, technical, developer — via
Jinja2 templates (`variants.py`), exportable to HTML, JSON, SARIF, or
Markdown (`exporters.py`, `cli.py`). SARIF export reuses the same
`gs_finding_export_sarif` bash function the rest of the framework uses,
rather than reimplementing SARIF in Python.

## Testing infrastructure

See [TESTING.md](TESTING.md) for what each test layer actually checks and how
to run them locally before pushing.

## Target architecture (vision, not all built yet)

Where this is heading — stated plainly as a target, not a claim about what's
shipped today. Some of this (the engagement/finding/policy layers, evidence,
reproducibility) is real and in place now; the SQLite storage layer and `gs`
CLI are active work-in-progress elsewhere in the project, not yet merged.

```
                     GHOSTSTRIKE
                          |
              +-----------+-----------+
              |                       |
             GUI                     CLI (gs)
              |                       |
              +-----------+-----------+
                          |
                   Application Core
                          |
         +----------------+----------------+
         |                |                |
   Engagement        Attack Graph       Operator AI
      Engine             Engine
         |                |                |
         +-------- Findings --------------+
         +-------- Evidence --------------+
         +-------- Timeline --------------+
         +-------- Retesting -------------+
                          |
                       SQLite
                          |
                    Policy Engine
                          |
                     Task Runner
                          |
      +-------------------+-------------------+
      |                   |                   |
 GhostStrike          External           Community
  modules               tools             modules
      |                   |                   |
      +-------------------+-------------------+
                          |
                     Linux System
```

Constraints that hold regardless of how much of the diagram above is built:
**no browser requirement, no mandatory SaaS backend, no mandatory account.**
GhostStrike is a local Linux tool first; a future Server/multi-tenant
deployment mode is a distinct, later, explicitly-optional thing — not a
replacement for running entirely on one machine with no network dependency
beyond the actual engagement's own targets.

Today's storage is flat JSON files under `bash_scripts_for_pentest/findings/`,
`runs/`, and `metrics/` (see `lib/engagement_query.py`), read through one
shared query layer rather than four separate implementations. The plan is a
storage abstraction (`EngagementRepository`-style: `get_findings()`,
`add_finding()`, etc.) that reads JSON today and SQLite once that lands,
so callers never need to know which backend is active.
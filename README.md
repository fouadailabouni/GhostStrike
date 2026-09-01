# GhostStrike

> © 2026 Fouad Ailabouni. All Rights Reserved. GhostStrike v3.0.0 [PHANTOM]

**GhostStrike** is a policy-gated offensive security assessment platform: a
CustomTkinter GUI over a modular bash framework of 165 pentest modules across
22 categories, with an optional AI Co-Pilot that operates under the exact
same authorization gate a manual run does.

![GhostStrike Screenshot](Repo.png)

## Why GhostStrike

Most collections of pentest scripts are just that — a collection. GhostStrike
enforces a real policy/trust/scope gate before any module fires, records
tamper-evident evidence chains with SHA-256 hashing, scores every run's
reproducibility 0–100, deduplicates findings across runs, and can build an
attack graph from what actually got found — not from what a script *should*
have found. Nothing here is a paper claim: the policy gate genuinely blocks
(exit code 77) when scope or authorization isn't satisfied, and it's verified
that way, not just documented that way.

## Install

```bash
git clone https://github.com/fouadailabouni/GhostStrike.git
cd GhostStrike
make install    # Python dependencies
make gui        # launch
```

Full requirements and setup: [docs/INSTALL.md](docs/INSTALL.md).

## Quick Start

```bash
cd bash_scripts_for_pentest
./repro_runner.sh 01-Network-Security/nmap_automation.sh 192.168.1.0/24
./benchmarks/run_benchmarks.sh --target all --report   # safe, against known-vulnerable lab targets
```

Full walkthrough: [docs/QUICKSTART.md](docs/QUICKSTART.md).

## Core Features

- **Policy engine** — every module calls `gs_policy_gate` before it runs; trust
  level, environment, and scope are all read from `policy.yaml` at runtime.
- **AI Co-Pilot** — 11 specialized agent personas (Red Team, Blue Team, Web
  Pentest, DFIR, CTF, and others) can drive modules through the same gate a
  manual run goes through.
- **Evidence & reproducibility** — SHA-256-hashed, signed evidence chains and
  a 0–100 reproducibility score per session.
- **Finding deduplication & attack graph** — cross-run dedup by CVE/host/MITRE
  overlap, and a host → service → finding attack graph built from real
  recorded findings, not inferred by an LLM.
- **Report Studio** — executive/technical/developer report variants, exported
  to HTML, JSON, SARIF, or Markdown.
- **Purple Mode** — maps executed techniques to real detection evidence
  (logged? alerted?) from recorded findings, computing a coverage score —
  never a guessed or hardcoded one; see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#purple-mode-libpurple_modepy-17-monitoring-detectionpurple_mode_validatorsh).
- **Encrypted credential vault** — PBKDF2-HMAC-SHA256 → AES-256-GCM; findings
  reference a credential ID, never the secret itself.

## Architecture

```
CyberToolkit/              GUI + AI Co-Pilot (Python)
  ai_engine/                 11 persona agents, MCP server
  report_studio/             Report generation
bash_scripts_for_pentest/  The module framework (bash)
  lib/                        Policy, evidence, vault, engagement, attack graph
  00-Framework-Core/ … 21-Bypass-Techniques/   22 module categories
```

Full breakdown, including the target architecture this is building toward
(a SQLite-backed engagement model, a `gs` CLI, Attack Graph v2):
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Safety Model

Authorization, scope enforcement, trust levels, and the vault are covered in
[docs/SAFETY_MODEL.md](docs/SAFETY_MODEL.md) — read this before pointing
GhostStrike at anything outside a lab environment.

## Module System

165 modules across 22 categories, all following the same argument-parsing +
policy-gate shape. See [docs/MODULE_SYSTEM.md](docs/MODULE_SYSTEM.md) for the
category breakdown and how to add a new module.

## Documentation

Full docs live in [`/docs`](docs/README.md): install, quick start, module
system, safety model, AI Co-Pilot, architecture, testing, and licensing.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

**GhostStrike Public Source License v1.0** — free to use, study, and modify;
modified versions must stay open under the same license; embedding in a
commercial product or offering it as a paid/hosted service requires a
separate OEM license. Full terms: [LICENSE](LICENSE). Licensing model and a
possible future Pro tier: [docs/LICENSING.md](docs/LICENSING.md).

## Legal Disclaimer

GhostStrike is provided exclusively for authorized security testing and
lawful penetration-testing engagements. Obtain explicit written authorization
from the owner of any system, network, or application before testing it.
Unauthorized use may violate computer fraud and abuse laws in your
jurisdiction. **If you do not have explicit written authorization to test a
target, do not use GhostStrike against it.**

---

> © 2026 Fouad Ailabouni. All Rights Reserved. For authorized security testing only.
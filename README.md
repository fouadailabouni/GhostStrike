<div align="center">

# 👻 GhostStrike

### Local-First Offensive Security Workspace for Linux

**Pentesting tools, evidence, attack paths, and AI-assisted analysis — in one governed engagement.**

No account · No browser · No mandatory cloud · Built for authorized security testing

[![CI](https://github.com/fouadailabouni/GhostStrike/actions/workflows/ci.yml/badge.svg)](https://github.com/fouadailabouni/GhostStrike/actions/workflows/ci.yml)
![Version](https://img.shields.io/badge/version-3.0.0-blue)
![Platform](https://img.shields.io/badge/platform-Linux-blue)
![Modules](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fraw.githubusercontent.com%2Ffouadailabouni%2FGhostStrike%2Fmain%2Fbash_scripts_for_pentest%2Fregistry.json&query=%24.total_modules&label=modules&color=blue)
[![License](https://img.shields.io/badge/license-GPSL--1.0-blue)](LICENSE)

![GhostStrike Screenshot](Repo.png)

<!-- TODO: replace with a purpose-built hero screenshot (engagement dashboard:
     exposure/attack-graph/operator panels) once that UI exists -- see
     docs/ROADMAP.md. This is the real, current GUI, not a mockup. -->

**Clone it. Run it. Pentest locally.**

</div>

---

## ⚡ 60-Second Start

```bash
git clone https://github.com/fouadailabouni/GhostStrike.git
cd GhostStrike
./install.sh
make gui
```

Recommended: Kali Linux. Also supported: Debian, Ubuntu, Parrot, or any Linux
with bash 4.0+ and Python 3.8+ (Windows: run under WSL2). Full setup, including
what `install.sh` actually checks and installs: [docs/INSTALL.md](docs/INSTALL.md).

<!-- TODO: record a real 20-40s terminal GIF of this flow (install -> engagement
     -> scope -> recon -> finding -> evidence -> graph -> report) and place it
     here -- "See GhostStrike in Action". Not faked in the meantime. -->

---

## Why GhostStrike

Most collections of pentest scripts are just that — a collection. GhostStrike
enforces a real policy/trust/scope gate before any module fires, records
tamper-evident evidence chains with SHA-256 hashing, scores every run's
reproducibility 0–100, deduplicates findings across runs, and builds an
attack graph from what actually got found — not from what a script *should*
have found. Nothing here is a paper claim: the policy gate genuinely blocks
(exit code 77) when scope or authorization isn't satisfied, and it's verified
that way, not just documented that way.

| Normal pentest workflow | GhostStrike |
|---|---|
| Tools scattered across terminals | One governed engagement |
| Results stored separately | Normalized findings |
| Manual evidence tracking | Automatic, SHA-256-hashed provenance |
| Vulnerabilities viewed individually | Attack graph across hosts/services/findings |
| Duplicate scanner findings | Cross-run deduplication |
| AI with unrestricted tool access | Policy-gated AI — same gate as manual runs |
| Screenshots and notes | Reproducible evidence, scored 0–100 |
| Cloud dependency | Local-first; cloud AI is optional |

## 🔒 Local by Design

- ✅ Runs on your own Linux workstation
- ✅ No GhostStrike account required
- ✅ No browser required
- ✅ No SaaS backend required
- ✅ Cloud AI optional — local models (Ollama, LM Studio) fully supported
- ✅ `GHOSTSTRIKE_OFFLINE=true` hard-blocks cloud AI backends at the code level, not just in docs
- ✅ Engagement data stays under your control

Your pentest does not need to become somebody else's cloud data.

## Key Capabilities

| 🛡️ Policy Gating | 🔗 Attack Graph | 📁 Evidence |
|---|---|---|
| Scope, trust level, and authorization enforced before every execution | Built from recorded findings — never inferred by an LLM | SHA-256-hashed, signed provenance chains |

| 🤖 Operator AI | 🟣 Purple Mode | 📄 Report Studio |
|---|---|---|
| 11 specialist agents; every action goes through the same gate a manual run does | Maps executed techniques to real detection evidence, not a guess | Executive/technical/developer variants → HTML, JSON, SARIF, Markdown |

### How the policy gate works

```
                   Operator
                      │
                     AI
                      │
                      ▼
              ┌──────────────┐
              │ POLICY GATE  │
              ├──────────────┤
              │ Scope        │
              │ Trust Level  │
              │ Environment  │
              │ Authorization│
              └──────┬───────┘
                     │
               Authorized?
                 /       \
               YES       NO
                │         │
                ▼         ▼
             Execute    BLOCK (exit 77)
```

**AI does not bypass the safety model. It goes through the same authorization
gate as manual execution** — see [docs/AI_COPILOT.md](docs/AI_COPILOT.md) and
[docs/SAFETY_MODEL.md](docs/SAFETY_MODEL.md).

### How the attack graph works

```
Internet
   │
   ▼
WEB-01
   │
   ├── HTTPS :443
   │       │
   │       ▼
   │    Finding GS-014
   │
   ▼
Credential
   │
   ▼
INTERNAL-02
```

**Built from recorded evidence, not an LLM hallucination** — every edge traces
back to a real finding with a real timestamp. See
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#purple-mode-libpurple_modepy-17-monitoring-detectionpurple_mode_validatorsh)
for how Purple Mode extends this to detection coverage.

## Works With Your Existing Arsenal

GhostStrike modules wrap and orchestrate real tools rather than reinventing
them — only integrations that actually exist in the module set, not planned
ones:

Nmap · Nuclei · Metasploit · Nikto · Masscan · sqlmap · Hydra · John the
Ripper · Hashcat · Impacket · BloodHound · NetExec · Aircrack-ng · Burp
Suite (import) · Nessus (import)

## <!-- STATS:MODULE_COUNT --> 172 <!-- /STATS --> Modules · <!-- STATS:CATEGORY_COUNT --> 22 <!-- /STATS --> Categories

```
Network              Web Application       Active Directory
Wireless             Database              Password Attacks
Social Engineering   System Security       Container Security
Mobile               Cloud                 Exploitation
Post-Exploitation    Reporting             Automation
Specialized Testing  Monitoring/Detection  Application Security
Lab Environment      IoT                   Bypass Techniques
Framework Core
```

[View the complete, machine-generated module inventory →](bash_scripts_for_pentest/registry.json)
Category/trust-level breakdown and how to add a module:
[docs/MODULE_SYSTEM.md](docs/MODULE_SYSTEM.md).

## Evidence & Reproducibility

Every module run through `repro_runner.sh` gets a per-session evidence
directory with SHA-256-hashed artifacts and MITRE ATT&CK tags, plus a 0–100
reproducibility score covering tool versions, logged commands, scope
documentation, and artifact hashing. Findings are deduplicated across runs by
CVE/host/MITRE overlap — never silently destroyed, only marked superseded.

## AI Operator

11 specialist agent personas (Red Team, Blue Team, Web Pentest, Bug Bounty,
DFIR, Reverse Engineering, WiFi, CTF, Purple Team, NLP Router, Output
Analyst) can drive modules on your behalf. Cloud (Claude, GPT) or fully local
(Ollama, LM Studio) — your choice, enforced at runtime, not just by
convention. Full model: [docs/AI_COPILOT.md](docs/AI_COPILOT.md).

## Local-First Architecture

```
              GhostStrike
                   │
          ┌────────┴────────┐
          │                 │
         GUI               AI
          │                 │
          └────────┬────────┘
                   ▼
             Engagement
                   │
        Findings ─ Graph ─ Evidence
                   │
              Policy Gate
                   │
              Module Runner
                   │
        ┌──────────┼──────────┐
        │          │          │
      Native     External   Custom
      Modules     Tools     Modules
```

Full directory layout, including today's storage (flat JSON) vs. the target
architecture (SQLite-backed): [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## What GhostStrike Is Not

- ✗ Not a replacement for Nmap, Burp Suite, or Metasploit
- ✗ Not an autonomous, unrestricted "AI hacker"
- ✗ Not cloud-only
- ✗ Not designed for unauthorized testing

✓ GhostStrike orchestrates and structures the offensive-security workflow
around those tools — governed, evidenced, and reproducible.

## Built For

🧑‍💻 Penetration testers · 🔴 Red teams · 🟣 Purple teams · 🔬 Security
researchers · 🎓 Cybersecurity labs · 🛡️ Internal security teams

## Quick Start: Your First Engagement

```bash
make gui
```

1. Create a new engagement and define its authorized scope.
2. Run a recon module against an in-scope target (or the bundled lab — see
   [examples/lab/README.md](examples/lab/README.md) for a safe target with
   zero setup).
3. Findings, evidence, and the attack graph populate as real results come in.
4. Generate a report from Report Studio.

Full walkthrough: [docs/QUICKSTART.md](docs/QUICKSTART.md). Prefer the
terminal? Direct module invocation (`repro_runner.sh`, individual scripts)
is documented under **Advanced / Headless Usage** in that same guide — the
GUI/engagement flow above is the primary way to use GhostStrike, not the
only way.

## Documentation

Full docs live in [`/docs`](docs/README.md): install, quick start,
architecture, safety model, AI Co-Pilot, module system, testing, licensing,
and roadmap.

## Project Status

| Feature | Status |
|---|---|
| Policy Engine | ✅ Stable |
| Evidence Engine | ✅ Stable |
| Encrypted Vault (AES-256-GCM) | ✅ Stable |
| Attack Graph v1 | ✅ Available |
| Finding Deduplication | ✅ Available |
| Report Studio | ✅ Available |
| `gs` CLI | 🧪 Beta |
| AI Co-Pilot | 🧪 Beta |
| Purple Mode (local backend) | 🧪 Beta |
| Module SDK | 🧪 Beta |
| SQLite Engagement Storage | 🧪 Beta (implemented, not yet the default) |
| Attack Graph v2 (Crown Jewels, GhostScore) | 🧪 Beta |
| Enterprise/SaaS deployment mode | 🛠 Not planned near-term |

## Roadmap

```
v3.1 Production Foundation
           ↓
v3.2 Engagement Engine
           ↓
v3.3 Attack Graph v2
           ↓
v3.4 Report Studio
           ↓
v4.0 Stable
```

Full sequencing and the adoption-first growth plan: [docs/ROADMAP.md](docs/ROADMAP.md).

## 🔬 Research

GhostStrike is being developed as both an operational security tool and a
research platform for evidence-grounded, policy-governed, reproducible
penetration testing. No published paper, benchmark dataset, or reproduction
package exists yet — this section will link them once they do, not before.

## Help Build GhostStrike

Looking for contributors interested in: pentesting modules · tool parsers ·
Attack Graph · Linux packaging · Report Studio · testing · documentation.

First contribution? Look for [`good first issue`](https://github.com/fouadailabouni/GhostStrike/issues).
How to contribute: [CONTRIBUTING.md](CONTRIBUTING.md).

## License

**GhostStrike Public Source License v1.0** — free to use, study, and modify;
modified versions must stay open under the same license; embedding in a
commercial product or offering it as a paid/hosted service requires a
separate OEM license. Full terms: [LICENSE](LICENSE). Licensing model and a
possible future Pro tier: [docs/LICENSING.md](docs/LICENSING.md).

## Responsible Disclosure

Found a vulnerability in GhostStrike itself (not a pentest finding produced
*by* GhostStrike against a target)? Please follow [SECURITY.md](SECURITY.md)
rather than opening a public issue.

## ⚠️ Authorized Security Testing Only

GhostStrike is provided exclusively for authorized security testing and
lawful penetration-testing engagements. Obtain explicit written authorization
from the owner of any system, network, or application before testing it.
Unauthorized use may violate computer fraud and abuse laws in your
jurisdiction. **If you do not have explicit written authorization to test a
target, do not use GhostStrike against it.**

---

<div align="center">

© 2026 Fouad Ailabouni. All Rights Reserved. GhostStrike v3.0.0 [PHANTOM].

</div>
# GhostStrike v3.0.0 [PHANTOM] — Documentation
> © 2026 Fouad Ailabouni. All Rights Reserved.
> For authorized penetration testing engagements only.

---

## Table of Contents

1. [Overview](#overview)
2. [Quick Start](#quick-start)
3. [Framework Architecture](#framework-architecture)
4. [GUI Reference](#gui-reference)
5. [Engagement Lifecycle](#engagement-lifecycle)
6. [Module Categories](#module-categories)
7. [Advanced Features](#advanced-features)
8. [Configuration](#configuration)
9. [Building and Packaging](#building-and-packaging)
10. [Dependencies](#dependencies)

---

## Overview

GhostStrike is a production-grade offensive security assessment platform:

- **103 penetration testing modules** across 22 attack categories — all fully operational
- **Python GUI launcher** (CustomTkinter dark theme, terminal aesthetic)
- **6 framework libraries** in `lib/` — policy engine, evidence provenance, finding ontology, reproducibility scoring, trust levels, credential vault
- **Engagement management** — full lifecycle from scope creation to archived reports
- **Benchmark mode** — automated validation against DVWA, Juice Shop, Metasploitable
- **CI/CD pipeline** — ShellCheck, bash-syntax, python-lint, schema validation on every push

**Platform:** Windows 10/11 with WSL2 or Git Bash
**Python:** 3.10+
**Version:** 3.0.0 [PHANTOM]
**Author:** Fouad Ailabouni

---

## Quick Start

### Launch GUI

```batch
GhostStrike.bat
```

Or directly:

```bash
cd CyberToolkit
python ghoststrike.py
```

### Run a module directly

```bash
cd "bash scripts for pentest"
cp scope.yml.template my_scope.yml
# edit my_scope.yml with engagement details

bash 01-Network-Security/nmap_automation.sh \
  --target 192.168.1.0/24 \
  --scope my_scope.yml \
  --output-dir /tmp/results

# Preview without executing
bash 02-Web-Application-Security/webapp_testing.sh \
  --target https://target.example.com --dry-run
```

### Run benchmarks

```bash
bash benchmarks/run_benchmarks.sh --target all --report
```

### Run tests

```bash
make test
# or
bash tests/test_framework.sh
```

---

## Framework Architecture

Every module execution passes through this pipeline:

```
Policy Gate  (lib/policy_engine.sh)
  └── Checks engagement ID, scope file, trust level, operator identity

Execution Wrapper  (repro_runner.sh)
  └── Snapshots tool versions + env, captures output, SHA256 artifact

Finding Ontology  (lib/finding_ontology.sh)
  └── UUID findings, MITRE ATT&CK alignment, CVSS v3.1 scoring

Evidence & Report  (lib/evidence.sh)
  └── Signed manifest, reproducibility score, SARIF 2.1.0, HTML report
```

### Library Files

| File | Purpose | Lines |
|------|---------|-------|
| `common.sh` | Core utilities, color constants, cleanup traps | 306 |
| `policy_engine.sh` | Pre-execution authorization gate | 274 |
| `evidence.sh` | SHA256-signed artifact collection, chain-of-custody | 673 |
| `finding_ontology.sh` | Normalized findings, CVSS/MITRE, SARIF export | 747 |
| `reproducibility.sh` | Session recording, 0–100 scoring, assessment replay | 919 |
| `trust_registry.sh` | Trust level registry for all 103 modules | 435 |
| `vault.sh` | AES-256-GCM encrypted credential store | — |

---

## GUI Reference

### Sidebar

| Element | Function |
|---------|----------|
| Search box | Filter modules by name, filename, description |
| ALL / OPERATIONAL | Filter by quality status |
| MODULES / VECTORS / ARMED | Live stats counter |
| THREAT LEVEL bar | Dynamically reflects selected module risk |
| Module list | Scrollable, color-coded by category |
| Engagements panel | Create, switch, archive engagements |
| Settings button (⚙) | Webhook URL and notification preferences |

### Action Buttons

| Button | Function |
|--------|----------|
| `▶ EXECUTE` | Run selected module — triggers Policy Gate first |
| `■ ABORT` | Kill the running process |
| `CLEAR` | Clear terminal output |
| `EXPORT` | Save terminal log to file |
| `BENCH` | Run benchmark suite (DVWA / Juice Shop / Metasploitable) |
| `FINDINGS` | Severity-sorted findings viewer table |
| `REPORT` | Generate HTML/PDF/Markdown report for current engagement |

### Trust Level Badges

| Badge | Color | Meaning |
|-------|-------|---------|
| `◈ SAFE_ENUM` | Blue | Passive only, production-safe |
| `◈ VALIDATION` | Green | Non-destructive active testing |
| `⚠ HIGH_IMPACT` | Amber | Active exploitation — written auth required |
| `☠ LAB_ONLY` | Red | Destructive — isolated lab environment only |

### Policy Gate

Every EXECUTE triggers a styled modal showing module name, trust level, environment constraints, and an authorization confirmation checkbox. HIGH_IMPACT shows an amber warning. LAB_ONLY shows a red skull. All decisions logged to `evidence/policy_audit.log`.

### Post-Execution Framework Summary

After every run, the terminal automatically prints:

```
  ── FRAMEWORK SUMMARY ──────────────────────────────────
  ◈ Evidence session : GS-2026-001
  ◈ Artifacts logged : 3
  ◈ Findings recorded: 5
  ◈ Critical/High    : 2  ← review findings
  ◈ Repro score      : 87/100 [█████████████████░░░] GOOD
```

### Arsenal Health Check

The sidebar ARSENAL STATUS panel shows which tools are installed (green dot) vs. missing (red dot) with a X/15 progress bar. Refreshes on startup and via the ↻ button. Module buttons show `[!]` if required tools are missing.

### Notifications

- Desktop toast notification when a module completes
- CRITICAL/HIGH finding popup during live execution
- Optional Slack/Teams/Discord webhook (Settings panel)

---

## Engagement Lifecycle

### 1. Create Engagement

Use the Engagements panel in the sidebar GUI, or create a scope file manually:

```yaml
# scope.yml
engagement_id: "GS-2026-CLIENTNAME-001"
owner: "ACME Corporation"
operator: "Tester Name"
environment: "staging"
authorization_ref: "SOW-2026-001"
target:
  - "192.168.1.0/24"
  - "app.example.com"
exclusions:
  - "192.168.1.1"
```

### 2. Execute Modules

Select an engagement in the GUI. All findings, artifacts, and sessions are automatically linked to the active engagement. The engagement ID and environment are injected as env vars before each module run.

### 3. Review Findings

Click `FINDINGS` in the GUI to see a severity-sorted table, or run:

```bash
# From bash scripts for pentest/
source lib/finding_ontology.sh
gs_finding_summary
```

### 4. Generate Report

Click `REPORT` in the GUI to open the report generation dialog. Select template (Technical / Executive / Compliance), output formats (HTML, Markdown, JSON/SARIF), and client branding fields. Or run directly:

```bash
bash 14-Reporting-Tools/pentest_report_generator.sh \
  --engagement-id "GS-2026-001" \
  --format html \
  --output-dir /tmp/reports
```

### 5. Archive

Archive completed engagements from the Engagements panel. Creates a timestamped zip of all evidence, findings, sessions, and reports.

---

## Module Categories

| # | Category | Scripts | Trust Levels |
|---|----------|---------|--------------|
| 00 | Framework Core | 5 | SAFE_ENUM |
| 01 | Network Security | 12 | SAFE_ENUM, VALIDATION |
| 02 | Web Application | 8 | VALIDATION, HIGH_IMPACT |
| 03 | Wireless Security | 2 | VALIDATION, HIGH_IMPACT |
| 04 | Database Security | 3 | HIGH_IMPACT |
| 05 | Active Directory | 3 | HIGH_IMPACT |
| 06 | Password Attacks | 3 | HIGH_IMPACT |
| 07 | Social Engineering | 3 | HIGH_IMPACT |
| 08 | System Security | 4 | SAFE_ENUM |
| 09 | Container Security | 1 | VALIDATION |
| 10 | Mobile Security | 2 | VALIDATION |
| 11 | Cloud Security | 4 | VALIDATION |
| 12 | Exploitation | 1 | LAB_ONLY |
| 13 | Post-Exploitation | 3 | LAB_ONLY, HIGH_IMPACT |
| 14 | Reporting Tools | 1 | SAFE_ENUM |
| 15 | Automation Tools | 2 | SAFE_ENUM, VALIDATION |
| 16 | Specialized Testing | 3 | HIGH_IMPACT |
| 17 | Monitoring/Detection | 4 | SAFE_ENUM |
| 18 | Application Security | 2 | SAFE_ENUM |
| 19 | Lab Environment | 1 | LAB_ONLY |
| 20 | IoT Security | 16 | VALIDATION, HIGH_IMPACT, LAB_ONLY |
| 21 | Bypass Techniques | 20 | HIGH_IMPACT, LAB_ONLY |

**Total: 103 modules — all ARMED (fully operational)**

---

## Advanced Features

### Policy Engine

```yaml
# policy.yaml
environments:
  lab:         # all trust levels permitted
  staging:     # HIGH_IMPACT + below
  production:  # SAFE_ENUM + VALIDATION only
```

Modules can also require explicit approval via `require_explicit_approval: true` in policy.yaml.

### Evidence Provenance

```bash
gs_evidence_init "GS-2026-001"
gs_evidence_collect "/tmp/scan.xml" "nmap -sV target" "Port scan" "Phase 1"
gs_evidence_sign_manifest   # SHA256-signs the manifest
```

### Reproducibility Scoring

Sessions are scored 0–100 across four dimensions and can be fully replayed:

```bash
bash assessment_replay.sh --session <session_id>
bash metrics/reproducibility_report.sh  # cross-session dashboard
```

### Credential Vault

```bash
source lib/vault.sh
gs_vault_store "target_admin" "admin" "Admin account"
PASSWORD=$(gs_vault_get "target_admin")       # decrypted at runtime, never on CLI
gs_vault_export_env "target_admin" TARGET    # exports TARGET_USER + TARGET_PASS
gs_vault_list                                 # shows all credentials (no passwords)
```

Encrypted with AES-256-GCM. Key from `GS_VAULT_KEY` env var. All operations logged.

### Benchmark Mode

```bash
bash benchmarks/run_benchmarks.sh --target all --report
# Targets: DVWA, Juice Shop, Metasploitable
# Scenarios: benchmarks/scenarios/dvwa.yaml, juiceshop.yaml, metasploitable.yaml
```

---

## Configuration

| File | Purpose |
|------|---------|
| `scope.yml.template` | Copy to create engagement scope file |
| `policy.yaml` | Trust level permissions, rate limits, module overrides |
| `.shellcheckrc` | ShellCheck linting rules for CI |
| `CyberToolkit/settings.json` | GUI: webhook URL, notification preferences |

---

## Building and Packaging

```bash
cd CyberToolkit
pip install -r requirements.txt
python ghoststrike.py      # run from source
python build.py            # build GhostStrike.exe
```

---

## Dependencies

### Python

| Package | Purpose |
|---------|---------|
| customtkinter | GUI framework |
| Pillow | Image handling |
| requests | HTTP client, webhooks |
| jsonschema | Finding schema validation |
| PyYAML | YAML parsing |
| rich | Terminal tables/progress bars |
| cryptography | Vault AES-256-GCM encryption |
| jinja2 | HTML report templates |
| markdown | Markdown report rendering |

Install: `pip install -r requirements.txt`

### System (bash modules)

nmap, sqlmap, hydra, hashcat, john, aircrack-ng, impacket, frida, trivy, binwalk, nuclei, metasploit, BloodHound, Prowler, gobuster, mosquitto-clients, coap-client

Install all: `bash 15-Automation-Tools/install_pentest_tools.sh`

---

## CI/CD

GitHub Actions runs on every push to main/master:

| Job | What it checks |
|-----|----------------|
| shellcheck | Lint all 103 scripts against .shellcheckrc |
| bash-syntax | `bash -n` on all scripts — 0 failures required |
| python-lint | py_compile + flake8 on CyberToolkit/ |
| schema-validation | finding.schema.json + policy.yaml + scope template |
| benchmark-dry-run | Benchmark script parse check |

Run locally:

```bash
make test        # full test suite
make lint        # shellcheck only
make syntax      # bash -n only
make benchmark   # benchmark dry-run
```

---

> GhostStrike v3.0.0 [PHANTOM]
> Authorized penetration testing only. Always obtain explicit written authorization.

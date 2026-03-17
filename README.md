# GhostStrike — Root Project Overview

> © 2026 Fouad Ailabouni. All Rights Reserved.

---

## Overview

**GhostStrike v3.0.0 [PHANTOM]** is a production-grade offensive security assessment platform built for professional penetration testers and red team operators. It combines a CustomTkinter-based GUI launcher with a modular bash scripting framework to deliver structured, evidence-backed, reproducible security assessments.

GhostStrike runs 103 discrete modules across 22 attack categories, enforces a policy engine before any module fires, records tamper-evident evidence chains, scores reproducibility on a 0–100 scale, and validates effectiveness through an integrated benchmark mode against known-vulnerable targets.

---
![GhostStrike Screenshot](Repo.png)
## Architecture

```
GhostStrike/
├── CyberToolkit/                   # GUI launcher (Python / CustomTkinter)
│   ├── ghoststrike.py              # Main GUI entry point
│   ├── cyber_toolkit.py            # Alternate launcher
│   └── assets/                     # Icons, images, branding
│
└── bash scripts for pentest/       # Core scripting framework
    ├── lib/                        # Shared library modules
    │   ├── common.sh
    │   ├── policy_engine.sh
    │   ├── evidence.sh
    │   ├── finding_ontology.sh
    │   ├── reproducibility.sh
    │   └── trust_registry.sh
    ├── schemas/                    # JSON schema definitions
    │   └── finding.schema.json
    ├── metrics/                    # Reproducibility reporting
    │   └── reproducibility_report.sh
    ├── benchmarks/                 # Benchmark validation mode
    │   ├── run_benchmarks.sh
    │   └── scenarios/
    ├── policy.yaml                 # Policy engine configuration
    ├── scope.yml.template          # Engagement scope template
    ├── repro_runner.sh             # Reproducibility wrapper
    ├── 00-Framework-Core/
    ├── 01-Network-Security/
    ├── 02-Web-Application-Security/
    ├── 03-Wireless-Security/
    ├── 04-Database-Security/
    ├── 05-Active-Directory/
    ├── 06-Password-Attacks/
    ├── 07-Social-Engineering/
    ├── 08-System-Security/
    ├── 09-Container-Security/
    ├── 10-Mobile-Security/
    ├── 11-Cloud-Security/
    ├── 12-Exploitation/
    ├── 13-Post-Exploitation/
    ├── 14-Reporting-Tools/
    ├── 15-Automation-Tools/
    ├── 16-Specialized-Testing/
    ├── 17-Monitoring-Detection/
    ├── 18-Application-Security/
    ├── 19-Lab-Environment/
    ├── 20-IoT-Security/
    └── 21-Bypass-Techniques/
```

---

## Quick Start

### Launch the GUI

```bash
python3 CyberToolkit/ghoststrike.py
```

Or via the alternate launcher:

```bash
python3 CyberToolkit/cyber_toolkit.py
```

### Run Scripts Directly

```bash
# Network scan with policy enforcement and evidence capture
cd "bash scripts for pentest"
./repro_runner.sh 01-Network-Security/nmap_automation.sh 192.168.1.0/24

# Web application assessment
./repro_runner.sh 02-Web-Application-Security/owasp_top10_scanner.sh https://target.example.com

# Run full benchmark suite
./benchmarks/run_benchmarks.sh --target all --report
```

### View Reproducibility Reports

```bash
cd "bash scripts for pentest"
./metrics/reproducibility_report.sh
```

---

## Framework Features

### Policy Engine
All modules pass through `lib/policy_engine.sh` before execution. The engine validates authorization tokens, enforces scope boundaries defined in `scope.yml`, checks module trust levels, and takes pre-execution snapshots. Modules that fail policy checks are blocked — they do not run, and the block is logged.

### Evidence Provenance
`lib/evidence.sh` initializes a per-session evidence directory, hashes all collected artifacts with SHA-256, attaches MITRE ATT&CK technique tags to each artifact, signs the final manifest, and writes a tamper-evident chain log. Export targets: structured JSON and SARIF 2.1.0.

### Reproducibility Scoring
`lib/reproducibility.sh` tracks tool versions, logged commands, scope documentation, and artifact hashing across each session. Sessions receive a 0–100 score and a badge (EXCELLENT / GOOD / FAIR / POOR). `repro_runner.sh` wraps any module with full reproducibility instrumentation.

### Finding Ontology
`lib/finding_ontology.sh` normalizes all findings against a strict schema (`schemas/finding.schema.json`), enforces required fields, maps CVSS v3 scores, associates MITRE ATT&CK techniques, and exports to SARIF 2.1.0 or structured JSON for downstream toolchain integration.

### Module Trust Levels
`lib/trust_registry.sh` maintains trust classifications for all 103 modules. Trust levels gate execution permissions and are surfaced in the GUI as threat level indicators. Unregistered or untrusted modules are blocked at policy check time.

### Benchmark Mode
`benchmarks/run_benchmarks.sh` validates module effectiveness against known-vulnerable targets (DVWA, Juice Shop, Metasploitable). Results are written to timestamped JSON reports in `benchmarks/results/`.

---

## Module Count

| Category | Scripts |
|---|---|
| 00-Framework-Core | 5 |
| 01-Network-Security | 12 |
| 02-Web-Application-Security | 8 |
| 03-Wireless-Security | 2 |
| 04-Database-Security | 3 |
| 05-Active-Directory | 3 |
| 06-Password-Attacks | 3 |
| 07-Social-Engineering | 3 |
| 08-System-Security | 4 |
| 09-Container-Security | 1 |
| 10-Mobile-Security | 2 |
| 11-Cloud-Security | 4 |
| 12-Exploitation | 1 |
| 13-Post-Exploitation | 3 |
| 14-Reporting-Tools | 1 |
| 15-Automation-Tools | 2 |
| 16-Specialized-Testing | 3 |
| 17-Monitoring-Detection | 4 |
| 18-Application-Security | 2 |
| 19-Lab-Environment | 1 |
| 20-IoT-Security | 16 |
| 21-Bypass-Techniques | 20 |
| **Total** | **103** |

---

## Requirements

| Component | Requirement |
|---|---|
| Python | 3.8 or higher |
| customtkinter | Latest stable |
| Pillow (PIL) | Latest stable |
| Bash | 4.0 or higher |
| nmap | Any recent version |
| sqlmap | Any recent version |
| nikto | Any recent version |
| metasploit-framework | Any recent version |
| jq | Any recent version (for JSON parsing) |
| python3-jsonschema | For schema validation |

Install core dependencies on Debian/Ubuntu:

```bash
sudo apt-get update
sudo apt-get install -y nmap masscan nikto dirb sqlmap metasploit-framework jq python3-pip
pip3 install customtkinter pillow jsonschema
```

---

## Legal Disclaimer

GhostStrike is provided exclusively for use in authorized security testing and lawful penetration testing engagements. You must obtain explicit written authorization from the owner of any system, network, or application before using these tools against it.

Unauthorized use of these tools against systems you do not own or do not have written permission to test may violate computer fraud and abuse laws in your jurisdiction. The authors and contributors of GhostStrike accept no liability for any damage, loss, or legal consequences resulting from unauthorized or unlawful use.

**If you do not have explicit written authorization to test a target, do not use GhostStrike against it.**

---

> © 2026 Fouad Ailabouni. All Rights Reserved.
> GhostStrike v3.0.0 [PHANTOM] — For authorized security testing only.

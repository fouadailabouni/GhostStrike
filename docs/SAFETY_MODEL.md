# Safety Model

GhostStrike is an offensive security tool. The safety model exists to make
sure every module runs inside an authorized, scoped engagement — not to slow
down legitimate use.

## The policy gate

Every module calls `gs_policy_gate "<module name>" "<trust level>" "<target>"`
once its own argument parsing is done. The gate:

1. Checks the module's trust level against what the current `GS_ENVIRONMENT`
   allows.
2. Validates the target against the engagement's scope file (real CIDR/domain
   matching via `lib/scope_check.py`, not substring matching).
3. Checks whether the module is on `policy.yaml`'s explicit-approval list.
4. Blocks with **exit code 77** if any check fails — the module does not run,
   and the block is logged.

`policy.yaml` is the source of truth, read at runtime via `lib/policy_query.py`
— changing policy doesn't require touching module code.

### Environments

| Environment | Allowed trust levels | Auth required |
|---|---|---|
| `lab` | all four | no |
| `staging` | SAFE_ENUM, VALIDATION, HIGH_IMPACT | yes — engagement ID + scope file |
| `production` | SAFE_ENUM, VALIDATION only | yes — full auth + scope + signed written authorization |

Authorization in `staging`/`production` requires `GS_ENGAGEMENT_ID`, a
`GS_SCOPE_FILE`, a signed written-authorization record, and operator +
audit logging — see `policy.yaml` for the exact fields.

### Trust levels

| Level | Meaning |
|---|---|
| `SAFE_ENUM` | Read-only enumeration, safe against any reachable target |
| `VALIDATION` | Confirms a specific finding; low blast radius |
| `HIGH_IMPACT` | Can meaningfully affect the target (exploitation, credential attacks, DoS-adjacent) |
| `LAB_ONLY` | Only makes sense against a lab target the operator controls (post-exploitation, persistence, evasion) |

`lib/trust_registry.sh` is the source of truth for per-module trust
classification; `bash_scripts_for_pentest/MODULE_INVENTORY.csv`
(regenerable via `tests/generate_module_inventory.sh`) is the machine-readable
record the GUI reads at runtime.

### Modules requiring explicit per-module approval

Nine modules require an explicit approval entry in `policy.yaml` regardless
of trust level or environment — `endpoint_detection_bypass.sh`,
`siem_log_evasion.sh`, `data_exfiltration_simulator.sh`,
`persistence_mechanisms.sh`, `phishing_campaign_automation.sh`,
`password_spraying_campaign.sh`, `metasploit_automation.sh`,
`ntlm_relay_tester.sh`, `sandbox_escape.sh`.

## The credential vault

`lib/vault.sh` stores credentials outside engagement JSON — findings and
engagement records reference a credential by ID (e.g. `CRED-001`), never the
secret itself. Encryption is real authenticated encryption, implemented in
`lib/vault_crypto.py`:

```
password → PBKDF2-HMAC-SHA256 (600,000 iterations) → 256-bit key
         → AES-256-GCM → encrypted credential file
```

GCM's authentication tag means a tampered ciphertext or wrong master password
fails loudly (a rejected decrypt), not silently (garbage plaintext) — the
opposite of the plain-CBC approach this replaced. The master password is
passed via an environment variable, never a CLI argument, and never touches
argv or an intermediate temp file.

## AI Co-Pilot redaction

Outbound data to an LLM provider goes through the same redaction path
regardless of which agent persona is active — see [AI_COPILOT.md](AI_COPILOT.md)
for the current scope of what's redacted and where that boundary sits today.

## Evidence and reproducibility

Every module run through `repro_runner.sh` gets a per-session evidence
directory (`lib/evidence.sh`) with SHA-256-hashed artifacts, MITRE ATT&CK
tags, and a signed manifest — plus a 0–100 reproducibility score
(`lib/reproducibility.sh`) covering tool versions, logged commands, scope
documentation, and artifact hashing.

## Status

The controls above are real and independently verified during development
(policy-gate blocking, vault encryption, evidence hashing). Authorization and
scope-validation code paths are being hardened toward a strict fail-closed
posture — if a check that's supposed to gate execution can't actually run,
the module should block rather than proceed — as an active, ongoing pass
across the codebase, not a one-time claim. Treat this document as describing
the intended and largely-implemented model, and check `CHANGELOG.md` (once it
exists) for what's landed in a given release before relying on it for a
production engagement.
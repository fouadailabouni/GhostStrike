# Security Policy

## Reporting a vulnerability in GhostStrike itself

If you find a real vulnerability in GhostStrike's own code — the policy
engine, the vault, the AI Co-Pilot's tool-calling surface, the SQLite/JSON
storage layer, or anything else that ships in this repository — please
report it privately rather than opening a public issue.

**Email:** fouadailabounifouad@gmail.com

Please include:

- A description of the vulnerability and its potential impact.
- Steps to reproduce it (a minimal example is ideal).
- The affected file(s)/function(s) if you've identified them.
- Whether you're aware of it being publicly known or exploited already.

You'll get an acknowledgment as soon as possible, and credit in the fix's
commit/changelog entry unless you'd prefer to stay anonymous.

## What this covers

This policy is for vulnerabilities *in GhostStrike's own code* — e.g., a
policy-gate bypass, a redaction gap that leaks secrets to an AI provider, a
command-injection path in a module or AI tool, or a cryptographic weakness
in the credential vault.

It does **not** cover:

- Findings that GhostStrike (correctly) surfaces *about a target you scanned*
  — that's the tool working as intended.
- Vulnerabilities in third-party tools GhostStrike wraps or integrates with
  (Nmap, Metasploit, sqlmap, etc.) — report those to their own maintainers.

## Supported versions

GhostStrike is pre-1.0 and moves quickly; security fixes land on `main`.
Once tagged releases begin (see [docs/ROADMAP.md](docs/ROADMAP.md)), this
section will specify which versions receive backported fixes.

## Scope note for a pentesting framework

GhostStrike ships offensive-security modules by design — that is not itself
a vulnerability report. This policy is about GhostStrike's *own* safety
controls (policy gating, scope enforcement, evidence integrity, credential
handling, AI redaction) failing to do what they claim to do.
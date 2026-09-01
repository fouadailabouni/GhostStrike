"""
GhostStrike Report Studio - Report Variants
===============================================
Three report shapes over the same ReportData:

  executive  -- severity counts, top findings, business-risk narrative,
                no raw command output. For a CISO/management audience.
  technical  -- full finding detail, evidence references, reproduction
                steps, CVSS vectors. For security engineers.
  developer  -- findings grouped by affected component/asset,
                remediation-first framing. For developers fixing issues.

Each renders Markdown via an inline Jinja2 template -- inline rather than
separate .j2 files on disk, since this is a small, cohesive package and
inline templates avoid a second file-resolution path to get wrong.

Copyright (C) 2026 Fouad Ailabouni. All rights reserved.
"""
from __future__ import annotations

from jinja2 import Template

from .data_sources import ReportData

_EXECUTIVE_TEMPLATE = Template("""\
# Executive Summary — {{ data.engagement.get('client', data.engagement_id) }}

**Engagement:** {{ data.engagement_id }}
**Environment:** {{ data.engagement.get('environment', 'n/a') }}
**Operator:** {{ data.engagement.get('operator', 'n/a') }}
**Findings:** {{ data.summary.get('finding_count', 0) }} across {{ data.summary.get('run_count', 0) }} module run(s)
**Average reproducibility score:** {% if data.summary.get('avg_reproducibility_score') is not none %}{{ data.summary.get('avg_reproducibility_score') }}/100{% else %}n/a{% endif %}

## Risk Overview

| Severity | Count |
|----------|-------|
{%- for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] %}
{%- set count = data.severity_counts.get(sev, 0) %}
{%- if count > 0 %}
| {{ sev }} | {{ count }} |
{%- endif %}
{%- endfor %}

## Top Findings

{%- set top = data.findings_sorted()[:10] %}
{%- if top %}
{%- for f in top %}
- **[{{ f.get('severity', 'INFO') }}]** {{ f.get('title', 'Untitled') }}{% if f.get('source_count', 1) > 1 %} _(confirmed by {{ f.get('source_count') }} sources)_{% endif %}
{%- endfor %}
{%- else %}
_No findings recorded for this engagement yet._
{%- endif %}

## Summary

{%- set crit = data.severity_counts.get('CRITICAL', 0) %}
{%- set high = data.severity_counts.get('HIGH', 0) %}
{% if crit > 0 %}
{{ crit }} critical finding(s) require immediate remediation before this environment should be considered production-ready.
{%- elif high > 0 %}
No critical findings, but {{ high }} high-severity issue(s) should be prioritized for remediation.
{%- elif data.summary.get('finding_count', 0) > 0 %}
No critical or high-severity findings were identified in this assessment.
{%- else %}
No findings have been recorded for this engagement yet.
{%- endif %}
""")

_TECHNICAL_TEMPLATE = Template("""\
# Technical Findings Report — {{ data.engagement_id }}

Generated from {{ data.summary.get('finding_count', 0) }} finding(s), {{ data.summary.get('run_count', 0) }} module run(s), \
{{ data.summary.get('repro_session_count', 0) }} reproducibility session(s).

{% for f in data.findings_sorted() %}
---

## [{{ f.get('severity', 'INFO') }}] {{ f.get('title', 'Untitled') }}

- **Finding ID:** `{{ f.get('finding_id', '') }}`
- **Module:** {{ f.get('module', 'n/a') }}
{%- if f.get('target') %}
- **Target:** {{ f.get('target', {}).get('host', '') }}{% if f.get('target', {}).get('port') %}:{{ f.get('target', {}).get('port') }}{% endif %}
{%- endif %}
{%- if f.get('cve_ids') %}
- **CVE(s):** {{ f.get('cve_ids') | join(', ') }}
{%- endif %}
{%- if f.get('cwe_ids') %}
- **CWE(s):** {{ f.get('cwe_ids') | join(', ') }}
{%- endif %}
{%- if f.get('cvss_score') %}
- **CVSS:** {{ f.get('cvss_score') }} ({{ f.get('cvss_vector', '') }})
{%- endif %}
{%- if f.get('mitre_attack') %}
- **MITRE ATT&CK:** {{ f.get('mitre_attack', {}).get('technique_id', '') }} ({{ f.get('mitre_attack', {}).get('tactic', '') }})
{%- endif %}
{%- if f.get('source_count', 1) > 1 %}
- **Confirmed by {{ f.get('source_count') }} sources** (merged findings: {{ f.get('merged_from', []) | join(', ') }}, confidence: {{ f.get('confidence', 'n/a') }})
{%- endif %}

**Description:**
{{ f.get('description', 'n/a') }}

{%- if f.get('impact') %}

**Impact:**
{{ f.get('impact') }}
{%- endif %}

{%- if f.get('evidence') %}

**Evidence:**
{%- set ev = f.get('evidence') %}
{%- if ev is mapping %}
- Artifact `{{ ev.get('artifact_id', 'n/a') }}` (sha256: `{{ ev.get('sha256', 'n/a') }}`)
{%- else %}
{%- for e in ev %}
- Artifact `{{ e.get('artifact_id', 'n/a') }}` (sha256: `{{ e.get('sha256', 'n/a') }}`)
{%- endfor %}
{%- endif %}
{%- endif %}

{%- if f.get('reproduction_steps') %}

**Reproduction Steps:**
{%- for step in f.get('reproduction_steps') %}
1. {{ step }}
{%- endfor %}
{%- endif %}

{%- if f.get('remediation') %}

**Remediation:**
{{ f.get('remediation') }}
{%- endif %}

{% endfor %}
""")

_DEVELOPER_TEMPLATE = Template("""\
# Developer Remediation Report — {{ data.engagement_id }}

Findings grouped by affected component. Fix the CRITICAL/HIGH items first.

{% set by_target = {} %}
{%- for f in data.findings_sorted() %}
{%- set key = f.get('target', {}).get('host', 'unspecified component') %}
{%- if key not in by_target %}{% set _ = by_target.__setitem__(key, []) %}{% endif %}
{%- set _ = by_target[key].append(f) %}
{%- endfor %}

{% for component, items in by_target.items() %}
## {{ component }}

{%- for f in items %}

### [{{ f.get('severity', 'INFO') }}] {{ f.get('title', 'Untitled') }}
{%- if f.get('mitre_attack', {}).get('technique_id') %} · SARIF rule `{{ f.get('mitre_attack', {}).get('technique_id') }}`{% endif %}

{{ f.get('description', '') }}

**Fix:** {{ f.get('remediation', 'No remediation recorded yet.') }}
{%- endfor %}
{% endfor %}
""")

_REMEDIATION_TEMPLATE = Template("""\
# Remediation Report — {{ data.engagement_id }}

Fixes only -- no reproduction detail, no raw evidence. For tracking what
needs to change, not how it was found.

{%- set actionable = data.findings_sorted() | selectattr('remediation') | list %}
{%- if actionable %}

| Severity | Finding | Remediation |
|----------|---------|-------------|
{%- for f in actionable %}
| {{ f.get('severity', 'INFO') }} | {{ f.get('title', 'Untitled') }} | {{ f.get('remediation', '') | replace('\\n', ' ') }} |
{%- endfor %}
{%- else %}
_No findings with recorded remediation guidance yet._
{%- endif %}
""")

_RETEST_TEMPLATE = Template("""\
# Retest Report — {{ data.engagement_id }}

Before/after status for every finding that has gone through the retest
workflow (`gs retest start` / `gs retest resolve`).

{%- if data.retests %}

| Finding | Original Status | Result | Retested At | Notes |
|---------|-----------------|--------|-------------|-------|
{%- for r in data.retests %}
| {{ r.get('finding_id', '') }} | {{ r.get('original_status', '') }} | {{ r.get('result') or 'pending' }} | {{ r.get('retested_at', '') }} | {{ r.get('notes', '') }} |
{%- endfor %}

## Still Vulnerable

{%- set still_vuln = data.retests | selectattr('result', 'equalto', 'still_vulnerable') | list %}
{%- if still_vuln %}
{%- for r in still_vuln %}
- {{ r.get('finding_id', '') }} -- {{ r.get('notes', 'No notes recorded.') }}
{%- endfor %}
{%- else %}
_No findings remain vulnerable after retest._
{%- endif %}
{%- else %}
_No retests have been recorded for this engagement yet. Run `gs retest start <finding_id>` to begin one._
{%- endif %}
""")

_VARIANTS = {
    "executive": _EXECUTIVE_TEMPLATE,
    "technical": _TECHNICAL_TEMPLATE,
    "developer": _DEVELOPER_TEMPLATE,
    "remediation": _REMEDIATION_TEMPLATE,
    "retest": _RETEST_TEMPLATE,
}


def render_markdown(variant: str, data: ReportData) -> str:
    template = _VARIANTS.get(variant)
    if template is None:
        raise ValueError(f"Unknown report variant: {variant!r} (expected one of {list(_VARIANTS)})")
    return template.render(data=data)
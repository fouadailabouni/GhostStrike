# Licensing

## GhostStrike Community (this repository)

Released under the **GhostStrike Public Source License v1.0** (inspired by,
but not a copy of, the Nmap Public Source License) — see [LICENSE](../LICENSE)
for the full text. In short:

- Free to view, study, run, and modify.
- Free to use for personal, educational, research, and authorized
  security-testing purposes.
- Modified versions/forks must stay under this same license and make their
  source available (copyleft, GPLv2-style).
- **Not** free to embed in a commercial product, redistribute as a paid or
  hosted service, or use as a material part of a paid consulting/managed
  security-testing deliverable — that requires a separate OEM/commercial
  license from the copyright owner (Section 4).
- The "GhostStrike" name and branding can't be used on a derivative or
  unrelated product without permission (Section 5).

Community is meant to be genuinely useful on its own — the core module
framework, the policy/trust/scope engine, the AI Co-Pilot, evidence and
reproducibility scoring, and the Engagement OS features (attack graph,
finding dedup, Report Studio, MCP server) all live here and stay here. This
is a deliberate choice: the roadmap for a future commercial tier should never
mean quietly hollowing out what's public.

## A future GhostStrike Pro tier

Not yet built, and not priced — this section exists to record the intended
shape so Community and Pro don't drift into an accidental feature war.

Candidates for a paid tier, roughly in the spirit of "things that make sense
to charge for because they represent ongoing cost or enterprise-specific
need," not "things pentesters need to do a real assessment":

- Custom company report templates (`.docx` template import/mapping)
- Advanced AI Operator capabilities beyond the Community agent set
- Advanced attack-path analytics / GhostScore-style prioritization at scale
- Cross-assessment comparison over time
- Premium third-party tool-output parsers (beyond the core import set)
- A community module hub with a curated/vetted premium module pack
- Commercial support and a professional update channel

Explicitly **not** the plan: removing core pentesting capability from
Community to push people toward Pro. If a feature is genuinely necessary to
run a real, professional assessment, it belongs in Community.

Pro stays a **local Linux tool, same as Community** — no server, no
mandatory SaaS backend, no mandatory account. The paid tier is about what
Pro adds on top of the same local-first architecture, not a different,
cloud-hosted product.

## Pricing

Deliberately undecided. The right sequence is adoption first (real pentesters
using GhostStrike regularly, real feedback on what's missing or annoying —
see [ROADMAP.md](ROADMAP.md)), pricing decisions second — not the other way
around. Early, non-committal illustrative bands worth keeping on record so a
future decision isn't made from scratch, **not a price list**:

- Community: free.
- Professional: roughly €300–600/year, depending on final feature set.
- Consultant/company license: roughly €1,500–5,000+/year, depending on seats.
- Enterprise/offline/air-gapped packages: €5,000–20,000+, later — support,
  custom modules, training, custom integrations.

When this section gets filled in for real, it should reflect what people
actually asked to pay for, not a number picked in advance.

## Questions

For anything not covered by the license terms above, or to discuss an OEM/
commercial license: **fouadailabounifouad@gmail.com**
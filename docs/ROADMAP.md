# Roadmap and Growth

## Adoption before revenue

The first goal is not revenue. In order:

1. 100 GitHub stars, then 500, then 1,000.
2. More importantly: 10 real pentesters using GhostStrike weekly, then 50.
3. Then ask them directly: *what do you hate about it?* Fix that.

Pricing and a Pro tier (see [LICENSING.md](LICENSING.md)) come after there's
real, regular usage to learn from — not before.

## The growth loop this is designed around

```
pentester downloads GhostStrike
           |
       runs an engagement
           |
     likes the Attack Graph
           |
      posts a screenshot
           |
   other pentesters try it
           |
   someone builds a module
           |
 GhostStrike gets more useful
           |
        more users
```

The Attack Graph and the module system are the intended viral loop — a
module someone builds for their own engagement is immediately useful to
everyone else, and a real (not simulated) attack graph is the kind of thing
that gets screenshotted and shared. Everything in the near-term roadmap
(CLI, import engine, Report Studio, Purple Mode) is in service of making
that loop actually work, not features for their own sake.

## Near-term sequencing

See the project's internal build-order notes for the current phase-by-phase
plan. In short: harden what exists (policy fail-closed behavior, the vault,
safe process execution) before adding surface area, then build the
SQLite-backed engagement model and `gs` CLI, then the higher-level features
(Attack Graph v2, Crown Jewels, GhostScore, Report Studio DOCX/PDF) that
depend on that foundation, then public launch, then iterate on real feedback.
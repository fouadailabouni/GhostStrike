# Contributing to GhostStrike

Thanks for considering a contribution. GhostStrike is a security tool used
against real systems (even if only lab ones) — a bit more process than a
typical project is intentional, not bureaucracy for its own sake.

## Before you start

- For anything non-trivial (a new module category, a change to the policy
  engine, a new report format), open an issue or discussion first. It's a
  lot cheaper to align on approach before code than after.
- Small fixes (a real bug, a typo, a missing `--help`) can go straight to a
  PR.

## Local setup

See [docs/INSTALL.md](docs/INSTALL.md). Then, before opening a PR:

```bash
make syntax     # bash -n every module
make lint       # ShellCheck every module
make test       # lib unit tests
bash tests/module_smoke_test.sh   # per-module smoke test
```

All four are exactly what CI runs — a clean local run means CI will pass.
See [docs/TESTING.md](docs/TESTING.md) for what each one actually checks.

## Adding a module

Follow the shape in [docs/MODULE_SYSTEM.md](docs/MODULE_SYSTEM.md):
`AUTHORIZATION DISCLAIMER` comment block, `set -euo pipefail`, source
`lib/common.sh`, parse args, call `gs_policy_gate` with an honest trust
level, then the real logic. Pick the trust level honestly — `LAB_ONLY` and
`HIGH_IMPACT` aren't optional extras, they're what keeps the policy gate
meaningful for everyone else's engagements too.

## Reporting a bug

Use the **Bug report** issue template. The most useful bug report includes:
the exact command you ran, the module/category, what you expected, what
actually happened, and (if it's not obviously sensitive) the actual output.

## Proposing a new module or tool integration

Use the **New module** or **New tool integration** template. Tell us what
gap it fills and, if you can, roughly which category it belongs in — the
existing 22 categories cover a lot of ground, and a new one should be a
genuine gap, not a one-off home for a single script.

## Reporting a security issue in GhostStrike itself

If you find a real vulnerability in GhostStrike's own code (not a pentest
finding produced *by* GhostStrike against a target) — email
**fouadailabounifouad@gmail.com** directly rather than opening a public
issue, so it can be fixed before it's public.

## Code of conduct

Be direct, be respectful, assume good faith. This is a tool for authorized
security work — contributions or discussion that promote unauthorized use
against real systems aren't welcome here.

## License

By contributing, you agree your contribution is licensed under the
**GhostStrike Public Source License v1.0** (see [LICENSE](LICENSE)) — the
same license as the rest of the project.
# Testing

GhostStrike has three distinct test layers. Running all of them locally
before pushing is exactly what `.github/workflows/ci.yml` does — a clean
local run means CI will pass.

| Layer | Command | Checks |
|---|---|---|
| Syntax | `make syntax` | `bash -n` on every module |
| Lint | `make lint` | ShellCheck (`-S error`) on every module |
| Lib unit tests | `make test` (`tests/test_framework.sh`) | `common.sh`, `evidence.sh`, `finding_ontology.sh`, `trust_registry.sh`, policy, reproducibility |
| Module smoke test | `bash tests/module_smoke_test.sh` | Every module: syntax, no-args behavior, `--help` behavior |
| Framework self-test | `bash bash_scripts_for_pentest/00-Framework-Core/framework_tester.sh` | Framework component checks (dependencies, JSON schema validity, script syntax across the whole tree) |
| Benchmarks | `./bash_scripts_for_pentest/benchmarks/run_benchmarks.sh --target all --report` | Real modules against real known-vulnerable targets (DVWA, Juice Shop, a Metasploitable-style lab container), scored against `benchmarks/scenarios/*.yaml` |

## Module smoke test specifics

`tests/module_smoke_test.sh` is deliberately narrow: it does **not** execute
attack logic against any target. For every module it checks:

1. `bash -n` — syntax.
2. No-args invocation — must not crash with "unbound variable", and must
   exit non-zero **unless** the module is a local-audit/no-target tool by
   design (tracked in the harness's `NO_TARGET_REQUIRED` allowlist).
3. `--help`/`-h` — must exit cleanly if supported; modules that don't
   support it are recorded as SKIP, not FAIL.

A module whose real no-args behavior is a network call (a cloud CLI, a
LinPEAS-style download) or a full-filesystem scan gets its no-args check run
under `GS_DRY_RUN=true` instead of a fixed timeout — see the
`DRY_RUN_FOR_NOARGS` list in the script itself. This was a real, repeated
source of CI flakiness before it was fixed this way: a fixed timeout budget
tuned against one machine (a dev laptop, or one generation of CI runner
image) isn't a property of the module, it's a property of whatever machine
happens to run it next.

## Writing a benchmark scenario

`benchmarks/scenarios/*.yaml` is the actual source of truth for expected
findings — not a parallel hardcoded list in `run_benchmarks.sh`. Each
scenario declares the target, the module + arguments to run, the target-flag
convention that module uses (`--target`, `--url`, or positional), and one or
more expected-finding substrings that must appear in real output for a PASS.
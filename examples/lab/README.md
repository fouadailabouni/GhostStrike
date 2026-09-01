# Safe Demo Target

Try GhostStrike against real, intentionally-vulnerable targets without
touching a real network — no separate demo infrastructure needed, this
points at the lab GhostStrike already ships with.

## Start it

```bash
cd bash_scripts_for_pentest/19-Lab-Environment
./docker_lab_setup.sh setup   # first time only: pulls/builds images
./docker_lab_setup.sh start
./docker_lab_setup.sh status  # confirm containers are up
```

This stands up DVWA, OWASP Juice Shop, WebGoat, NodeGoat, WordPress+MySQL,
PostgreSQL, MongoDB, an SSH target, an FTP target, and a Telnet target —
all safe to attack, all local.

## A 5-minute walkthrough

```bash
# 1. Confirm the lab is reachable
./docker_lab_setup.sh status

# 2. Run a real scan against it (from bash_scripts_for_pentest/)
cd ..
./repro_runner.sh 01-Network-Security/nmap_automation.sh 127.0.0.1

# 3. Run the benchmark suite against known-vulnerable targets in the lab --
#    this is the fastest way to see multiple real modules produce real
#    findings against real (if intentionally broken) software.
./benchmarks/run_benchmarks.sh --target dvwa --report
./benchmarks/run_benchmarks.sh --target juiceshop --report

# 4. Check reproducibility scoring for what you just ran
./metrics/reproducibility_report.sh
```

## Stop it when you're done

```bash
cd bash_scripts_for_pentest/19-Lab-Environment
./docker_lab_setup.sh stop
```

## `gs demo` (planned, not built yet)

Once the `gs` CLI exists (see [docs/ROADMAP.md](../../docs/ROADMAP.md)),
`gs demo` should wrap the setup + walkthrough above into one command and a
guided tutorial — this file is the content that command should drive, not
a separate demo environment to keep in sync.
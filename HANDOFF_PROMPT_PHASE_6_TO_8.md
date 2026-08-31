Continue the GhostStrike production-readiness effort. Read the full plan first:

    C:\Users\Fouad Ailabouni\.claude\plans\go-throug-all-sc-distributed-babbage.md

Read its "Current Status" section at the top carefully — it tells you exactly
what's done (Phases 0-3, partially) and what's not. Your job is Phases 6, 7,
8a, and 8b, in that order. The user wants this in production today, so work
through all four phases end-to-end in this session rather than stopping after
one — check in only if you hit a real decision point the plan doesn't already
resolve.

## Environment you're working in

- Repo: `C:\Users\Fouad Ailabouni\Desktop\GhostStrike` (a git repo, nothing
  committed yet this whole effort — it's all sitting as working-tree changes).
- This is a Windows machine. For anything that needs real bash execution (not
  just `bash -n` syntax checks), use WSL2: `wsl.exe -d Ubuntu-24.04 -u root --
  <command>`. That distro already has python3, pyyaml, shellcheck, jq, nmap,
  Docker, Metasploit Framework, and `pymetasploit3` installed.
- A live Docker lab is running (or can be restarted with
  `bash_scripts_for_pentest/19-Lab-Environment/docker_lab_setup.sh start` from
  inside `pentest_lab/`): DVWA (:8080), WebGoat (:8081), Juice Shop (:8082),
  NodeGoat (:8083), WordPress (:8084), MySQL/PostgreSQL/MongoDB, SSH (:2222),
  FTP (:21), Telnet (:23), and a Metasploitable-style stand-in container.
- The regression gate for any script changes is `tests/module_smoke_test.sh` —
  run it after every batch of edits. It checks syntax, "no crash with no args,"
  and correct non-zero exit on missing required args.
- The module inventory is `bash_scripts_for_pentest/MODULE_INVENTORY.csv`,
  regenerate with `tests/generate_module_inventory.sh` after adding/changing
  modules.

## Gotchas already discovered this session — don't rediscover these the hard way

1. **The Edit tool on this Windows machine has intermittently reintroduced
   CRLF line endings** on some edited files (cause not fully root-caused).
   After editing any `.sh` file, run `file <path>` and check for `CRLF` in the
   output. If found, strip it: `tr -d '\r' < file > file.tmp && mv file.tmp file`.
   This has caused real, confusing syntax failures twice already.
2. **`common.sh` sets `IFS=$'\n\t'`** (deliberately excluding space) for strict-
   mode safety. Any `read var1 var2 <<< "space separated string"` pattern in a
   script that sources `common.sh` will silently fail to split on spaces unless
   you write `IFS=' ' read -r var1 var2 <<< "$str"`. This bit the session-manager
   work badly before being caught.
3. **Never splice dynamic bash values into `python3 -c "..."` source text.**
   Pass them as `sys.argv` elements or environment variables instead. This
   codebase had three real code-injection vulnerabilities from exactly this
   anti-pattern (closed this session) — don't reintroduce it in new code.
4. **`show_help()` functions must not hardcode `exit 0`** if they're called from
   both the `-h` path and error paths — one file this session had an actual
   infinite loop because of this plus a missing `shift`. Check any new
   `show_help`-style function you touch or write.
5. Git Bash (this environment's default shell) mangles paths starting with
   `/mnt/c/...` unless you `export MSYS_NO_PATHCONV=1` first, or you're calling
   `wsl.exe` directly (which handles it fine) vs. piping through further
   Git-Bash-native commands.

## Phase 6 — Documentation reconciliation

Full spec is in the plan file. Summary: regenerate `SCRIPT_INVENTORY.md` to
reflect the real script count and trust levels (it will be higher again after
Phase 8a adds more scripts — do Phase 6 AFTER 8a for this reason, or expect to
touch it twice), rewrite `bash_scripts_for_pentest/lib/README.md` to match the
actual function signatures in the code (it currently documents a fictional
API), and rewrite or retire `FRAMEWORK_IMPLEMENTATION_SUMMARY.md` (describes an
abandoned architecture and falsely claims "100% COMPLETE").

**Suggested actual order given the dependency**: do Phase 7 and 8a/8b first,
then come back to Phase 6 last so you're not documenting a moving target. The
plan technically lists Phase 6 before 7/8, but the "why last" reasoning in
Phase 6's own section (every earlier phase changes the facts these docs
describe) applies just as much to 8a's new scripts — use your judgment, but
don't write Phase 6's docs before 8a's scripts land if you can help it.

## Phase 7 — GUI integration

Full spec in the plan file. Key points:
- `CyberToolkit/ghoststrike.py`'s `_new_engagement_dialog` (around line 2133)
  captures a `scope_file` that is never actually passed to script invocation.
  Wire it into `_build_shell_command` as `--scope <path>` or `GS_SCOPE_FILE`.
- The GUI has its own hardcoded Python `TRUST_REGISTRY` dict that has already
  drifted from `lib/trust_registry.sh` (which was fixed this session for the
  `system_config_audit.sh` basename-collision bug — the GUI's copy doesn't
  know about that fix). Make one side authoritative and have the other query it,
  don't maintain two copies.
- Do NOT attempt full live-technique verification of all modules against real
  targets as part of this phase — that's explicitly called out as a separate,
  unbounded workstream in the plan.

## Phase 8a — Port 45 extra modules from PhantomOps

Source: `C:\Users\Fouad Ailabouni\Downloads\PhantomOps\PhantomOps`

This is a real sibling project the user built previously and lost, now found.
It has a `.NET`/ABP backend (`src/PhantomOps.*`) and an Angular frontend
(`angular/`) — **do not port either of those**, the user was explicit about
this. Only `scripts/` (167 bash modules vs GhostStrike's 122) and
`CyberToolkit/ai_engine/` (the AI agent layer) are in scope.

Re-run this diff yourself first (don't trust a hardcoded list, the trees may
have moved since this was last checked):

```bash
GHOST="/c/Users/Fouad Ailabouni/Desktop/GhostStrike/bash_scripts_for_pentest"
PHANTOM="/c/Users/Fouad Ailabouni/Downloads/PhantomOps/PhantomOps/scripts"
comm -23 <(find "$PHANTOM" -name "*.sh" -not -path "*/lib/*" -exec basename {} \; | sort -u) \
         <(find "$GHOST" -name "*.sh" -not -path "*/lib/*" -exec basename {} \; | sort -u)
```

As of this session that's 45 scripts, including a much deeper Active Directory
attack chain (Kerberoasting, ASREP-roasting, DCSync, Pass-the-Hash/Ticket,
BloodHound, lateral movement/persistence, NTLM relay/Responder), Azure/GCP
cloud audits, CIS/lynis/OpenSCAP compliance checkers, and real-tool wrappers
(nuclei, masscan, hydra). This is almost certainly the real source of the
paper's "168 governed modules" claim — GhostStrike is an earlier/incomplete
snapshot missing these.

For each of the 45:
1. Copy into GhostStrike's matching category directory.
2. **Check whether it depends on PhantomOps's (possibly older/less-hardened)
   `lib/` behavior.** GhostStrike's `lib/common.sh`, `policy_engine.sh`,
   `evidence.sh`, `finding_ontology.sh`, and `vault.sh` were significantly
   hardened this session (3 injection vulnerabilities closed, a missing
   double-source guard added, real scope enforcement added via
   `lib/scope_check.py`). Don't let a ported script overwrite or bypass these
   fixes.
3. Run it through the exact same process the 38 already-wired GhostStrike
   modules went through: confirm it sources `lib/common.sh` +
   `lib/policy_engine.sh`, find its target-argument variable, insert
   `gs_policy_gate "$(basename "$0")" "<TRUST_LEVEL>" "$<TARGET>"` right after
   its own argument validation completes, fix any `set -u`/argument-parsing
   bugs found along the way (this pattern showed up in roughly a third of the
   38 modules already wired — expect a similar rate here).
4. Run `tests/module_smoke_test.sh` after each batch of ~10-15 scripts.
5. Regenerate `MODULE_INVENTORY.csv`.

## Phase 8b — Port the AI agent engine into the existing GUI

Source: `C:\Users\Fouad Ailabouni\Downloads\PhantomOps\PhantomOps\CyberToolkit\ai_engine\`

This is a real, working implementation with:
- `agents/`: `base_agent.py` + 10 named personas (red_team, blue_team,
  web_pentest, bug_bounty, dfir, reverse_eng, wifi, ctf, purple_team,
  nlp_router) **plus an 11th, `output_analyst_agent.py`**, not mentioned in
  the paper's "10 specialized agents" claim — read it and decide whether it's
  an internal helper or a real 11th agent worth documenting as such.
- `guardrails.py`, `reasoning_engine.py` (the ReAct loop — confirm the actual
  iteration bound in code; don't trust the paper's "30" claim blindly),
  `model_provider.py` (pluggable LLM backend), `findings_extractor.py`,
  `mitre_mapper.py`, `tracer.py`.
- `tools/`: `phantomops_runner.py` (the governed runner — needs the most
  adaptation), `shell_executor.py`, `c2_listener.py`, `code_runner.py`,
  `http_analyzer.py`, `js_analyzer.py`, `network_capture.py`,
  `osint_orchestrator.py`, `shodan_censys.py`.
- `prompts/`: one `.md` per agent persona.

What to do:
1. Copy `ai_engine/` wholesale into GhostStrike's `CyberToolkit/` as a starting
   point.
2. Read `CyberToolkit/phantomops.py` in the source project to see how it wires
   `ai_engine` into its own GUI — that's your integration reference, but the
   actual target is GhostStrike's `ghoststrike.py`, not a new file. **GhostStrike
   stays a desktop CustomTkinter app** — do not build a web frontend or wire in
   the ABP/Angular pieces.
3. Rewrite `tools/phantomops_runner.py`'s module-dispatch logic so it calls
   GhostStrike's real `bash_scripts_for_pentest/` modules through the actual
   `gs_policy_gate` path (Phase 3's work) — **the AI must go through the exact
   same policy/trust/scope gate a manual GUI run does, with zero exceptions.**
   This is the one non-negotiable design requirement carried over from the
   original spec.
4. Add a Manual / AI Co-Pilot mode toggle to `ghoststrike.py`. Reuse
   GhostStrike's existing findings DB (`bash_scripts_for_pentest/findings/*.json`)
   rather than whatever PhantomOps used.
5. Store any LLM API keys via GhostStrike's hardened `lib/vault.sh`, not
   whatever config/`.env` pattern PhantomOps used (check what it did, and
   don't copy it if it's weaker).
6. Decide on and implement outbound-data redaction (reuse `gs_redact` from
   `lib/common.sh`) before findings/scan data goes to an external LLM API —
   this was flagged as an open decision in the original plan and never
   resolved.
7. `CyberToolkit/api.py` in the source project — read it before assuming
   anything; it may be a REST layer for the Angular frontend (out of scope) or
   something else worth keeping.

## Verification before calling this done

- All 45 newly-ported modules pass `tests/module_smoke_test.sh` at the same
  bar as the existing 122 (0 syntax failures, no unbound-variable crashes,
  correct non-zero exit on missing required args).
- Spot-check a few of the new AD/cloud modules by actually running them
  against the lab (or a quickly-stood-up AD lab if warranted) — don't just
  trust that syntax-valid means functionally correct.
- Enable AI Co-Pilot mode and confirm: a suggested HIGH_IMPACT step still
  triggers the full policy gate and requires the same approval a manual run
  would; an out-of-scope suggestion is blocked the same way a manual
  out-of-scope run is; if redaction is implemented, inspect an actual outbound
  API payload and confirm sensitive data is stripped.
- Launch `ghoststrike.py` for real and click through: new engagement with a
  scope file → run a module → confirm scope enforcement actually blocks an
  out-of-scope target end-to-end from GUI click to bash exit code.

Report back with what's done, what's still open, and any bugs found along the
way (there will be some — every phase so far has surfaced real, previously-
unknown bugs; that's expected, not a sign something's wrong with your approach).

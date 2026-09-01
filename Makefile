# GhostStrike v3.0.0 [PHANTOM] — Developer Makefile
# © 2026 Fouad Ailabouni. All Rights Reserved.
#
# Usage:
#   make help       — show available targets
#   make test       — run full framework test suite
#   make lint       — shellcheck all scripts
#   make syntax     — bash -n all scripts
#   make gui        — launch the GUI
#   make install    — install Python dependencies
#   make benchmark  — run benchmark dry-run
#   make clean      — remove generated artifacts

SCRIPTS_DIR := bash_scripts_for_pentest
CYTOOLKIT   := CyberToolkit
PYTHON      := python3

.PHONY: help test lint syntax benchmark install clean gui \
        vault-init evidence-clean findings-clean

# ── Default target ──────────────────────────────────────────
help:
	@echo ""
	@echo "  GhostStrike v3.0.0 [PHANTOM] — Available targets"
	@echo "  ─────────────────────────────────────────────────"
	@echo "  make test        Run the full framework test suite"
	@echo "  make lint        Run ShellCheck on all 103+ scripts"
	@echo "  make syntax      Run bash -n on all scripts"
	@echo "  make benchmark   Run benchmark dry-run check"
	@echo "  make install     Install Python dependencies"
	@echo "  make gui         Launch the GhostStrike GUI"
	@echo "  make clean       Remove generated evidence/findings/sessions"
	@echo "  make vault-init  Initialize the credential vault"
	@echo ""

# ── Testing ─────────────────────────────────────────────────
test:
	@echo "Running GhostStrike framework test suite..."
	@bash tests/test_framework.sh

# ── Linting ─────────────────────────────────────────────────
lint:
	@echo "Running ShellCheck on all scripts..."
	@FAILED=0; PASSED=0; \
	while IFS= read -r -d '' f; do \
	  if shellcheck --rcfile "$(SCRIPTS_DIR)/.shellcheckrc" "$$f" 2>/dev/null; then \
	    PASSED=$$((PASSED + 1)); \
	  else \
	    echo "  WARNING: $$f"; \
	    FAILED=$$((FAILED + 1)); \
	  fi; \
	done < <(find "$(SCRIPTS_DIR)" -name "*.sh" -print0); \
	TOTAL=$$((PASSED + FAILED)); \
	echo "ShellCheck: $$PASSED/$$TOTAL passed"

# ── Syntax check ─────────────────────────────────────────────
syntax:
	@echo "Running bash -n syntax check on all scripts..."
	@FAILED=0; PASSED=0; \
	while IFS= read -r -d '' f; do \
	  if bash -n "$$f" 2>/dev/null; then \
	    PASSED=$$((PASSED + 1)); \
	  else \
	    echo "  SYNTAX ERROR: $$f"; \
	    FAILED=$$((FAILED + 1)); \
	  fi; \
	done < <(find "$(SCRIPTS_DIR)" -name "*.sh" -print0); \
	TOTAL=$$((PASSED + FAILED)); \
	echo "Syntax: $$PASSED/$$TOTAL passed"; \
	[ "$$FAILED" -eq 0 ]

# ── Benchmarks ───────────────────────────────────────────────
benchmark:
	@echo "Running benchmark dry-run..."
	@bash -n "$(SCRIPTS_DIR)/benchmarks/run_benchmarks.sh" && \
	  echo "Benchmark script: syntax OK"
	@$(PYTHON) -c "import yaml; [yaml.safe_load(open(f)) for f in \
	  ['$(SCRIPTS_DIR)/benchmarks/scenarios/dvwa.yaml', \
	   '$(SCRIPTS_DIR)/benchmarks/scenarios/juiceshop.yaml', \
	   '$(SCRIPTS_DIR)/benchmarks/scenarios/metasploitable.yaml']]" && \
	  echo "Benchmark scenarios: all valid YAML"

# ── Python install ───────────────────────────────────────────
install:
	@echo "Installing Python dependencies..."
	@pip install -r $(CYTOOLKIT)/requirements.txt || \
		pip install --break-system-packages -r $(CYTOOLKIT)/requirements.txt

# ── GUI launcher ────────────────────────────────────────────
gui:
	@cd $(CYTOOLKIT) && $(PYTHON) ghoststrike.py

# ── Vault ───────────────────────────────────────────────────
vault-init:
	@echo "Initializing GhostStrike credential vault..."
	@cd "$(SCRIPTS_DIR)" && bash -c 'source lib/vault.sh && gs_vault_init'

# ── Cleanup ──────────────────────────────────────────────────
clean: evidence-clean findings-clean
	@echo "Cleaned generated artifacts."

evidence-clean:
	@echo "Removing evidence/ directory..."
	@rm -rf "$(SCRIPTS_DIR)/evidence"

findings-clean:
	@echo "Removing findings/ directory..."
	@rm -rf "$(SCRIPTS_DIR)/findings"

sessions-clean:
	@echo "Removing repro sessions..."
	@rm -rf "$(SCRIPTS_DIR)/metrics/repro_sessions"

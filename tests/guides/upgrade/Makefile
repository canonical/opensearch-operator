# Upgrade-guide test script generation and execution.
#
# Run from the project root:
#   make -f tests/guides/upgrade/Makefile
#
# Or from the tests/guides/upgrade/ directory:
#   make

# ---------------------------------------------------------------------------
# Python interpreter
# ---------------------------------------------------------------------------
PYTHON   ?= python3

# ---------------------------------------------------------------------------
# Path variables
# ---------------------------------------------------------------------------
THIS_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

# Three levels up from tests/guides/upgrade/ reaches the project root.
ROOT     := $(abspath $(THIS_DIR)../../..)
EXTRACT  := $(THIS_DIR)extract_guide_tasks.py
GUIDE    := $(ROOT)/docs/how-to/upgrade.md

# ---------------------------------------------------------------------------
# Spread configuration
# ---------------------------------------------------------------------------
SPREAD     ?= spread
SPREAD_JOB ?= multipass:ubuntu-24.04-64:tasks/

# ---------------------------------------------------------------------------
# Target: all  (default) — regenerate generated task scripts
# ---------------------------------------------------------------------------
.PHONY: all
all: extract

# ---------------------------------------------------------------------------
# Target: extract — regenerate task scripts from the guide
# ---------------------------------------------------------------------------
.PHONY: extract
extract:
	cd $(THIS_DIR) && $(PYTHON) extract_guide_tasks.py $(GUIDE) ./tasks/

# ---------------------------------------------------------------------------
# Target: test  (abort on first failure)
# ---------------------------------------------------------------------------
.PHONY: test
test: extract
	cd $(THIS_DIR) && $(SPREAD) -abend -vv $(SPREAD_JOB)

# ---------------------------------------------------------------------------
# Target: test-continue  (run all stages even if some fail)
# ---------------------------------------------------------------------------
.PHONY: test-continue
test-continue: extract
	cd $(THIS_DIR) && $(SPREAD) -vv $(SPREAD_JOB)

# ---------------------------------------------------------------------------
# Target: test-debug  (abort + interactive shell on failure)
# ---------------------------------------------------------------------------
.PHONY: test-debug
test-debug: extract
	cd $(THIS_DIR) && $(SPREAD) -abend -vv -debug $(SPREAD_JOB)

# ---------------------------------------------------------------------------
# Target: help
# ---------------------------------------------------------------------------
.PHONY: help
help:
	@echo "Usage: make -f tests/guides/upgrade/Makefile [target]"
	@echo ""
	@echo "Targets:"
	@echo "  all            Regenerate task scripts (default)"
	@echo "  extract        Regenerate task scripts from docs/how-to/upgrade.md"
	@echo "  test           Run the upgrade-guide suite (abort on first failure)"
	@echo "  test-continue  Run all stages even if earlier ones fail"
	@echo "  test-debug     Drop into an interactive shell on failure"
	@echo "  help           Show this help message"

# Tutorial test script generation and execution.
#
# Run from the project root:
#   make -f tests/tutorial/Makefile
#
# Or from the tests/tutorial/ directory:
#   make

# ---------------------------------------------------------------------------
# Python interpreter
# ---------------------------------------------------------------------------
PYTHON   ?= python3

# ---------------------------------------------------------------------------
# Path variables
# ---------------------------------------------------------------------------
THIS_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

# Two levels up from tests/tutorial/ reaches the project root.
ROOT     := $(abspath $(THIS_DIR)/../..)

EXTRACT  := $(THIS_DIR)extract_commands.py

# ---------------------------------------------------------------------------
# Script → Markdown mapping (SCRIPTS)
# ---------------------------------------------------------------------------
# Each entry is a colon-separated pair:  output.sh:source.md
# Execution order is determined by the ``priority`` field in each file's
# ``<!-- test:spread ... -->`` metadata block.
SCRIPTS := \
    $(THIS_DIR)1-set-up-the-environment.sh:$(ROOT)/docs/tutorial/1-set-up-the-environment.md \
    $(THIS_DIR)2-deploy-opensearch.sh:$(ROOT)/docs/tutorial/2-deploy-opensearch.md \
    $(THIS_DIR)3-enable-encryption.sh:$(ROOT)/docs/tutorial/3-enable-encryption.md \
    $(THIS_DIR)4-integrate-with-a-client-application.sh:$(ROOT)/docs/tutorial/4-integrate-with-a-client-application.md \
    $(THIS_DIR)5-manage-passwords.sh:$(ROOT)/docs/tutorial/5-manage-passwords.md \
    $(THIS_DIR)6-scale-horizontally.sh:$(ROOT)/docs/tutorial/6-scale-horizontally.md \
    $(THIS_DIR)7-clean-up-the-environment.sh:$(ROOT)/docs/tutorial/7-clean-up-the-environment.md

OUTPUTS := $(foreach pair,$(SCRIPTS),$(word 1,$(subst :, ,$(pair))))

# ---------------------------------------------------------------------------
# rel — convert an absolute path to a root-relative path
# ---------------------------------------------------------------------------
rel = $(patsubst $(ROOT)/%,%,$(1))

# ---------------------------------------------------------------------------
# Target: all  (default)
# ---------------------------------------------------------------------------
.PHONY: all
all: $(OUTPUTS)

# ---------------------------------------------------------------------------
# Per-script build rules
# ---------------------------------------------------------------------------
define make_rule
$(word 1,$(subst :, ,$(1))): $(word 2,$(subst :, ,$(1))) $(EXTRACT)
	cd $(ROOT) && $(PYTHON) $(call rel,$(EXTRACT)) $(call rel,$(word 2,$(subst :, ,$(1)))) $(call rel,$(word 1,$(subst :, ,$(1))))
endef
$(foreach pair,$(SCRIPTS),$(eval $(call make_rule,$(pair))))

# ---------------------------------------------------------------------------
# Target: extract  (unconditional full regeneration via directory discovery)
# ---------------------------------------------------------------------------
.PHONY: extract
extract:
	cd $(ROOT) && $(PYTHON) $(call rel,$(EXTRACT)) docs/tutorial/ tests/tutorial/

# ---------------------------------------------------------------------------
# Spread configuration
# ---------------------------------------------------------------------------
SPREAD     ?= spread
SPREAD_JOB ?= multipass:ubuntu-24.04-64:tests/tutorial/

# ---------------------------------------------------------------------------
# Target: test  (abort on first failure)
# ---------------------------------------------------------------------------
.PHONY: test
test: extract
	$(SPREAD) -abend -vv $(SPREAD_JOB)

# ---------------------------------------------------------------------------
# Target: test-continue  (run all stages even if some fail)
# ---------------------------------------------------------------------------
.PHONY: test-continue
test-continue: extract
	$(SPREAD) -vv $(SPREAD_JOB)

# ---------------------------------------------------------------------------
# Target: test-debug  (abort + interactive shell on failure)
# ---------------------------------------------------------------------------
.PHONY: test-debug
test-debug: extract
	$(SPREAD) -abend -vv -debug $(SPREAD_JOB)

# ---------------------------------------------------------------------------
# Target: help
# ---------------------------------------------------------------------------
.PHONY: help
help:
	@echo "Usage: make -f tests/tutorial/Makefile [target]"
	@echo ""
	@echo "Targets:"
	@echo "  all            Regenerate scripts that are out of date (default)"
	@echo "  extract        Unconditionally regenerate all scripts"
	@echo "  test           Run the tutorial suite (abort on first failure)"
	@echo "  test-continue  Run all stages even if earlier ones fail"
	@echo "  test-debug     Drop into an interactive shell on failure"
	@echo "  help           Show this help message"

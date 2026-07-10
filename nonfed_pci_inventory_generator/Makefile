# Convenience targets for the PCI DSS v4.0.1 inventory generator.
.PHONY: help venv install dev-install run run-verbose lint type test clean

PYTHON ?= python3
VENV   ?= .venv
BIN     = $(VENV)/bin

help:
	@echo "Targets:"
	@echo "  make venv          Create virtualenv in $(VENV)"
	@echo "  make install       Install runtime deps into the venv"
	@echo "  make dev-install   Install runtime + dev deps (editable)"
	@echo "  make run           Run the inventory (single account, ambient creds)"
	@echo "  make run-verbose   Run with --verbose"
	@echo "  make lint          ruff check"
	@echo "  make type          mypy type check"
	@echo "  make test          pytest"
	@echo "  make clean         Remove venv + caches"

venv:
	$(PYTHON) -m venv $(VENV)

install: venv
	$(BIN)/pip install --upgrade pip
	$(BIN)/pip install -r requirements.txt

dev-install: venv
	$(BIN)/pip install --upgrade pip
	$(BIN)/pip install -e ".[dev]"

run:
	$(BIN)/pci-inventory

run-verbose:
	$(BIN)/pci-inventory --verbose

lint:
	$(BIN)/ruff check src

type:
	$(BIN)/mypy src

test:
	$(BIN)/pytest -q

clean:
	rm -rf $(VENV) .pytest_cache .mypy_cache .ruff_cache **/__pycache__ src/**/__pycache__

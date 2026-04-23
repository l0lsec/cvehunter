.PHONY: install test lint format typecheck run serve benchmark clean check help

VENV := .venv
PYTHON := $(VENV)/bin/python
PIP := $(VENV)/bin/pip

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'

install: ## Install package in editable mode with dev dependencies
	$(PIP) install -e ".[dev]"

test: ## Run test suite
	$(PYTHON) -m pytest tests/ -v

lint: ## Run linter checks
	$(PYTHON) -m ruff check src/ tests/

format: ## Auto-format code
	$(PYTHON) -m ruff format src/ tests/
	$(PYTHON) -m ruff check --fix src/ tests/

typecheck: ## Run type checker
	$(PYTHON) -m mypy src/cvehunter/

check: lint typecheck test ## Run lint, typecheck, and tests

run: ## Run pipeline for a CVE (usage: make run CVE=CVE-2024-12345)
	$(PYTHON) -m cvehunter.cli run $(CVE)

serve: ## Start the API server with auto-reload
	$(PYTHON) -m uvicorn cvehunter.api.main:app --reload --host 0.0.0.0 --port 8000

benchmark: ## Run the benchmark suite
	$(PYTHON) -m cvehunter.benchmark

clean: ## Remove Docker resources, artifacts, and caches
	@echo "Cleaning Docker compose projects..."
	-docker compose ls --filter name=cvehunter -q | xargs -r -I{} docker compose -p {} down -v --remove-orphans
	@echo "Removing artifacts and caches..."
	rm -rf artifacts/ .pytest_cache/ .mypy_cache/ .ruff_cache/
	rm -f cvehunter.db
	find src/ -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find tests/ -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

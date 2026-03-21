.DEFAULT_GOAL := help

.PHONY: help install dev test lint format typecheck coverage check docs docs-serve clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'

install: ## Install package
	pip install -e .

dev: ## Install with dev dependencies
	pip install -e ".[dev]"
	pre-commit install

test: ## Run tests
	pytest tests/ -v

lint: ## Run linter
	ruff check src/ tests/
	ruff format --check src/ tests/

format: ## Format code
	ruff format src/ tests/

typecheck: ## Run type checker
	mypy src/aegis/

coverage: ## Run tests with coverage
	pytest tests/ --cov=aegis --cov-report=term-missing --cov-report=html
	@echo "Open htmlcov/index.html for the full report"

check: ## Run all checks (lint + typecheck + test)
	@echo "==> Lint"
	ruff check src/ tests/
	ruff format --check src/ tests/
	@echo "==> Type check"
	mypy src/aegis/
	@echo "==> Tests"
	pytest tests/ -q
	@echo "==> All checks passed!"

docs: ## Build documentation
	mkdocs build --strict

docs-serve: ## Serve documentation locally
	mkdocs serve

clean: ## Remove build artifacts
	rm -rf build/ dist/ *.egg-info src/*.egg-info .pytest_cache .mypy_cache htmlcov .coverage site/
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

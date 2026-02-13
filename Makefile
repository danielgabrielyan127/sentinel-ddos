# ──────────────────────────────────────────────────
#  Sentinel DDoS — Makefile
# ──────────────────────────────────────────────────

.PHONY: help dev test lint build up down logs attack-test dashboard

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-18s\033[0m %s\n", $$1, $$2}'

# ── Development ──────────────────────────────────

dev: ## Run backend in dev mode
	uvicorn src.main:app --reload --host 0.0.0.0 --port 8000

dashboard: ## Run dashboard dev server
	cd dashboard && npm run dev

test: ## Run tests
	pytest -v --tb=short

lint: ## Lint Python code
	ruff check src/ tests/ simulator/

format: ## Format Python code
	ruff format src/ tests/ simulator/

# ── Docker ───────────────────────────────────────

build: ## Build Docker image
	docker-compose build

up: ## Start production stack
	docker-compose up -d

down: ## Stop production stack
	docker-compose down

logs: ## Tail Sentinel logs
	docker-compose logs -f sentinel

# ── Testing Lab ──────────────────────────────────

test-lab-up: ## Start test lab (Sentinel + target + Redis)
	docker-compose -f docker-compose.test.yml up -d

test-lab-down: ## Stop test lab
	docker-compose -f docker-compose.test.yml down

attack-test: ## Run HTTP Flood simulation against test lab
	python -m simulator.attack_simulator http_flood

# ── Cleanup ──────────────────────────────────────

clean: ## Remove build artifacts
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	rm -rf .pytest_cache dist build *.egg-info

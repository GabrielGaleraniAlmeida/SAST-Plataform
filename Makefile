.PHONY: up down build test coverage lint scan shell-api logs

# ============================================================
# Docker Compose
# ============================================================
up:
	docker compose up -d --build --wait --wait-timeout 900
	@echo "========================================================"
	@echo "🚀 PLATAFORMA SAST & DEVSECOPS INICIADA COM SUCESSO!"
	@echo "========================================================"
	@echo "📊 Dashboard React : http://localhost:3000"
	@echo "⚙️  API (Swagger)   : http://localhost:8000/docs"
	@echo "🧠 LLM (Ollama)    : localhost:11434"
	@echo "========================================================"

down:
	docker compose down

build:
	docker compose build

# ============================================================
# Testes
# ============================================================

## Roda todos os testes com saída verbose
test:
	pytest tests/ -v

## Roda testes com relatório de cobertura (HTML em htmlcov/)
coverage:
	pytest tests/ -v --cov=services --cov-report=html --cov-report=term-missing --cov-fail-under=70
	@echo "📈 Relatório HTML gerado em: htmlcov/index.html"

## Roda linter (flake8 ou ruff)
lint:
	@command -v ruff >/dev/null 2>&1 && ruff check services/ tests/ || flake8 services/ tests/ --max-line-length=120 --exclude=__pycache__,.venv,venv

# ============================================================
# Utilitários
# ============================================================
scan:
	docker compose exec api python -m pytest tests/

shell-api:
	docker compose exec api bash

logs:
	docker compose logs -f

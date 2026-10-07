.PHONY: up down build test scan shell-api logs

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
	docker-compose down

build:
	docker-compose build

test:
	pytest tests/ -v

scan:
	docker-compose exec api python -m pytest tests/

shell-api:
	docker-compose exec api bash

logs:
	docker-compose logs -f

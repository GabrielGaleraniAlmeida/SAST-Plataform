#!/bin/bash

# Sobe os containers em background
docker-compose up -d

# Imprime o banner
echo "========================================================"
echo "🚀 PLATAFORMA SAST & DEVSECOPS INICIADA COM SUCESSO!"
echo "========================================================"
echo "📊 Dashboard React : http://localhost:3000"
echo "⚙️  API (Swagger)   : http://localhost:8000/docs"
echo "🧠 LLM (Ollama)    : localhost:11434"
echo "========================================================"

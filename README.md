# Plataforma SAST & DevSecOps

> Protótipo acadêmico open-source de **Static Application Security Testing** com análise Python, taint analysis limitada, IA local opcional e integração DevSecOps.

[![Python](https://img.shields.io/badge/Python-3.11-blue?logo=python)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110-green?logo=fastapi)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-18-blue?logo=react)](https://react.dev)
[![Docker](https://img.shields.io/badge/Docker-Compose-blue?logo=docker)](https://docker.com)
[![Ollama](https://img.shields.io/badge/Ollama-Llama3-purple)](https://ollama.ai)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

---

## Funcionalidades

- **Análise primária:** regras heurísticas e taint analysis limitadas para Python. JavaScript e Java têm apenas parsing experimental; não há paridade de regras SAST.
- **Motor SAST Heurístico:** 15 regras nativas de segurança mapeadas para vulnerabilidades OWASP/CWE.
- **Taint analysis experimental:** fluxo source→sink limitado, com atribuições, coleções comuns e chamadas no mesmo arquivo; veja as limitações abaixo.
- **Integração com LLM:** Ollama local pode classificar findings e sugerir remediações. A classificação é indicativa e não remove findings automaticamente.
- **Dashboard React:** Interface de visualização com tabelas de taint flows, badges de severidade e métricas.
- **DevSecOps:** GitHub Actions com gates de Bandit, Semgrep, Trivy e auditoria de dependências.
- **Autenticação por API Key:** Header `X-API-Key`; sem chave, a autenticação fica desabilitada apenas no modo local de desenvolvimento.

---

## Configuração

### 1. Copiar variáveis de ambiente

```bash
cp .env.example .env
```

Edite o arquivo `.env` com uma senha exclusiva e mantenha-a sincronizada em `POSTGRES_PASSWORD`, `DATABASE_URL` e `DATABASE_SYNC_URL`:

```bash
# Banco de dados
POSTGRES_PASSWORD=senha_forte_aqui
# Use a mesma senha no DATABASE_URL de conexão do banco.

# Segurança da API (vazio somente no desenvolvimento local)
# Gere uma chave segura:
# python -c "import secrets; print(secrets.token_hex(32))"
SAST_API_KEY=

# Modelo de IA (llama3 é o padrão)
OLLAMA_MODEL=llama3
```

> ⚠️ **NUNCA** versione o arquivo `.env`. Ele já está no `.gitignore`.
> Atualize também a senha correspondente em `DATABASE_URL` ao definir `POSTGRES_PASSWORD`.
> Configure `SAST_API_KEY` fora do modo local de desenvolvimento. Gere a chave com o comando acima e guarde-a em um gerenciador de segredos ou variável de ambiente protegida; não a inclua no repositório.

Quando `SAST_API_KEY` estiver configurada, envie-a em todas as chamadas às rotas de scans,
vulnerabilidades e estatísticas:

```bash
curl http://localhost:8000/api/v1/scans \
  -H "X-API-Key: sua_chave"
```

### 2. Subir a plataforma

```bash
make up
# ou
docker compose up -d --build --wait
```

As portas publicadas pelo Compose ficam vinculadas a `127.0.0.1`, apropriado para demonstração local; não é uma configuração de implantação em produção.

---

## Quick Start (Docker Compose)

Na primeira inicialização, o Compose baixa o modelo Ollama (≈4 GB); aguarde alguns minutos.

| Serviço | URL |
|---------|-----|
| **API REST + Swagger** | http://localhost:8000/docs |
| **Dashboard** | http://localhost:3000 |
| **Ollama** | http://localhost:11434 |

---

## Demonstração

### Passo a Passo: Scan de um Arquivo

**1. Enviar um arquivo para análise (scan síncrono):**

```bash
curl -X POST http://localhost:8000/api/v1/scan/file \
     -H "Content-Type: application/json" \
     -d '{
       "filename": "app.py",
       "content": "from flask import request\nimport os\n\ndef handler():\n    cmd = request.args.get(\"cmd\")\n    os.system(cmd)",
       "language": "python"
     }'
```

**2. Resposta com findings:**

O JSON abaixo é um exemplo ilustrativo de formato, não uma evidência de execução capturada. Esse endpoint analisa o arquivo de forma síncrona e não cria um scan persistido para o dashboard.

```json
{
  "findings": [
    {
      "rule_id": "SAST-TAINT-001",
      "rule_name": "Fluxo de Dados Não Sanitizado",
      "severity": "critical",
      "title": "Tainted flow to os.system",
      "description": "Input inseguro atinge 'os.system' sem sanitização.",
      "line_number": 6
    }
  ],
  "total": 1,
  "files": [{"file_path": "app.py", "vulnerabilities_count": 1}]
}
```

**3. Scan de repositório completo (assíncrono):**

```bash
# Criar scan
curl -X POST http://localhost:8000/api/v1/scans \
     -H "Content-Type: application/json" \
     -d '{"repository_url": "https://github.com/exemplo/repo", "branch": "main", "language": "python"}'

# Verificar status (polling)
curl http://localhost:8000/api/v1/scans/1
```

---

## Arquitetura

A plataforma segue o **C4 Model** em 3 níveis — veja [`docs/C4_ARCHITECTURE.md`](docs/C4_ARCHITECTURE.md).

```
┌─────────────────────────────────────────────────────────────┐
│                   Plataforma SAST                           │
│                                                             │
│  Dashboard (3000) ──→ API FastAPI (8000) ──→ PostgreSQL     │
│                              │                              │
│                              ├──→ Redis Broker              │
│                              │         │                    │
│                              │    Celery Worker             │
│                              │         │                    │
│                              │    ┌────┴──────────┐        │
│                              │    Analyzer (8002)  │        │
│                              │    └────────────────┘        │
│                              │         │                    │
│                              │    ┌────┴──────────┐        │
│                              │    AI Service (8003) │       │
│                              │    └────────────────┘        │
│                              │         │                    │
│                              │    Ollama (11434)            │
└─────────────────────────────────────────────────────────────┘
```

> Ver diagrama interativo Mermaid completo em [C4_ARCHITECTURE.md](docs/C4_ARCHITECTURE.md)

---

## Testes

### Executar testes

```bash
# Instalar dependências de teste e serviços
python -m pip install -r services/analyzer/requirements.txt
python -m pip install -r services/api/requirements.txt
python -m pip install -r services/ai/requirements.txt
python -m pip install -r requirements-test.txt

# Rodar todos os testes com output verbose
make test
# ou: pytest tests/ -v

# Cobertura de código com relatório HTML
make coverage
# O comando aplica o limite configurado e gera htmlcov/index.html.

# Linter de Python
make lint

# Validar o frontend
cd services/dashboard
npm ci
npm run lint
npm run build
```

O CI aplica um limite de cobertura de 70%; o relatório gerado localmente mede o código coberto pela suíte atual. Consulte [`docs/VALIDATION.md`](docs/VALIDATION.md) para os casos conhecidos e para as limitações do corpus.

### Estrutura dos testes

| Arquivo | Cobertura |
|---------|-----------|
| `tests/test_taint_analysis.py` | Taint limitado, fontes/sinks, sanitização contextual, escopos, coleções e chamadas |
| `tests/test_parser.py` | Parser Python (erros de sintaxe, detecção de linguagem), JS fallback |
| `tests/test_scanner.py` | Pipeline completo (rules + taint integrados) |
| `tests/test_rules.py` | Regras SAST individuais |
| `tests/test_ollama_client.py`, `tests/test_ai_analyzer.py` | Cliente Ollama, classificação, remediação, resposta inválida e fallback |

`tests/fixtures/taint_cases.json` é um corpus pequeno e rotulado, executado pelo teste de benchmark. Ele não é uma avaliação independente de precisão/recall e não representa código real abrangente.

---

## Segurança — Regras SAST Implementadas

O motor possui 15 regras heurísticas; a análise de taint é um detector adicional.

| # | Rule ID | Vulnerabilidade | CWE | Severidade |
|---|---------|-----------------|-----|------------|
| 1 | SAST-001 | Hardcoded Password / Secret | CWE-798 | 🔴 Critical |
| 2 | SAST-002 | SQL Injection | CWE-89 | 🔴 Critical |
| 3 | SAST-003 | Command Injection | CWE-78 | 🔴 Critical |
| 4 | SAST-004 | Path Traversal | CWE-22 | 🟠 High |
| 5 | SAST-005 | Hardcoded IP Address or Internal URL | CWE-1041 | ⚪ Low |
| 6 | SAST-006 | Use of eval() / exec() | CWE-95 | 🟠 High |
| 7 | SAST-007 | Weak Cryptographic Algorithm | CWE-327 | 🟡 Medium |
| 8 | SAST-008 | Insecure Random Number Generator | CWE-338 | 🟡 Medium |
| 9 | SAST-009 | Debug Mode Enabled | CWE-94 | 🟠 High |
| 10 | SAST-010 | Missing HTTPS — Insecure HTTP URL | CWE-319 | 🟡 Medium |
| 11 | SAST-011 | Unsafe Template Rendering / XSS | CWE-79 | 🟠 High |
| 12 | SAST-012 | Server-Side Request Forgery (SSRF) | CWE-918 | 🟠 High |
| 13 | SAST-013 | Insecure Deserialization | CWE-502 | 🔴 Critical |
| 14 | SAST-014 | Missing Authentication Decorator | CWE-306 | 🟡 Medium |
| 15 | SAST-015 | Sensitive Data Exposure in Logs | CWE-532 | 🟠 High |
| — | SAST-TAINT-001 | Unsanitized Source-to-Sink Flow | CWE-20 | 🔴 Critical |

---

## Decisões de Arquitetura

Veja [`docs/DECISIONS.md`](docs/DECISIONS.md) para os ADRs completos:

- **ADR-001:** Celery + Redis para processamento assíncrono
- **ADR-002:** Ollama/Llama3 para IA local (sem envio de código a APIs externas)
- **ADR-003:** Python `ast` nativo vs tree-sitter

---

## Limitações Conhecidas

| Funcionalidade | Status | Observação |
|---------------|--------|------------|
| Python | Primária | Parsing via `ast`; conjunto heurístico de regras e taint limitado, sem garantia de cobertura completa da linguagem |
| Taint Analysis | Experimental | Uma passagem aproximada por instruções e fluxo limitado entre funções no mesmo arquivo |
| JavaScript / TypeScript | Experimental | Parsing Tree-sitter/fallback; sem conjunto próprio completo de regras SAST nem taint analysis |
| Java | Experimental | Parsing Tree-sitter/fallback; sem conjunto próprio completo de regras SAST nem taint analysis |
| Análise de bytecode | ❌ Não suportado | Apenas código-fonte |
| Taint entre arquivos (cross-file) | ❌ Não suportado | Exigiria grafo de chamadas completo |
| Análise de configuração (IaC) | Não implementada | Scanners de terceiros no workflow não significam suporte IaC próprio |

O parsing Tree-sitter não equivale a análise SAST completa. A plataforma é um protótipo acadêmico; não declare ou use como pronta para produção sem controles, cobertura de testes, avaliação de eficácia e revisão operacional apropriados.

Não há screenshots ou evidências visuais de dashboard versionadas nesta documentação.

---

## Documentação Completa

- 📐 [Arquitetura C4 (3 níveis)](docs/C4_ARCHITECTURE.md)
- 📋 [API Reference](docs/API.md)
- 📝 [Architecture Decision Records](docs/DECISIONS.md)

---

Desenvolvido para o Projeto Integrador de Engenharia de Software.

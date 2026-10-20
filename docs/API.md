# API Reference — Plataforma SAST & DevSecOps

**Base URL:** `http://localhost:8000`
**Formato:** JSON (`Content-Type: application/json`)
**Autenticação:** Header `X-API-Key: <sua_chave>` (desabilitada somente quando `SAST_API_KEY` está vazia em desenvolvimento local — veja [Configuração](../README.md))
**Documentação interativa:** `http://localhost:8000/docs` (Swagger UI)

---

## Sumário de Endpoints

| Método | Endpoint | Descrição |
|--------|----------|-----------|
| `GET` | `/api/v1/health` | Health check da plataforma |
| `POST` | `/api/v1/scan/file` | Analisa um trecho de código diretamente |
| `POST` | `/api/v1/scans` | Cria um novo scan de repositório (assíncrono) |
| `GET` | `/api/v1/scans` | Lista todos os scans (paginado) |
| `GET` | `/api/v1/scans/{id}` | Detalha um scan específico |
| `DELETE` | `/api/v1/scans/{id}` | Remove um scan e seus findings |
| `POST` | `/api/v1/scans/{id}/cancel` | Cancela um scan em andamento |
| `GET` | `/api/v1/vulnerabilities` | Lista vulnerabilidades (paginado, filtros) |
| `GET` | `/api/v1/vulnerabilities/{id}` | Detalha uma vulnerabilidade |
| `PATCH` | `/api/v1/vulnerabilities/{id}/suppress` | Suprime (aceita) uma vulnerabilidade |
| `GET` | `/api/v1/stats/summary` | Resumo geral da plataforma |
| `GET` | `/api/v1/stats/trends` | Tendência de vulnerabilidades por dia |
| `GET` | `/api/v1/stats/top-files` | Top arquivos com mais vulnerabilidades |
| `GET` | `/api/v1/stats/by-rule` | Vulnerabilidades agrupadas por regra |
| `GET` | `/api/v1/stats/severity-distribution` | Distribuição por severidade |

---

## Health Check

### `GET /api/v1/health`

Verifica a conectividade com o banco PostgreSQL e o Redis. Não verifica o Analyzer nem o serviço de IA.

**Response 200:**
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "database": "ok",
  "redis": "ok"
}
```

Quando o banco ou o Redis não puder ser acessado, a API responde HTTP `503`, `status: "degraded"` e inclui a condição correspondente no campo `database` ou `redis`.

---

## Scan de Arquivo (Síncrono)

### `POST /api/v1/scan/file`

Envia um trecho de código diretamente para análise e recebe o resultado imediatamente. Ideal para uso em pipelines CI/CD.

**Request:**
```json
{
  "filename": "app.py",
  "content": "import os\nfrom flask import request\ndef handler():\n    cmd = request.args.get('cmd')\n    os.system(cmd)",
  "language": "python"
}
```

**Response 200:**
```json
{
  "findings": [
    {
      "file_path": "app.py",
      "line_number": 5,
      "column": 4,
      "rule_id": "SAST-003",
      "rule_name": "Command Injection via os.system",
      "severity": "critical",
      "cwe_id": "CWE-78",
      "title": "Command Injection via os.system",
      "description": "Dado não sanitizado de request.args passado para os.system().",
      "code_snippet": "os.system(cmd)",
      "confidence": 0.9,
      "language": "python"
    },
    {
      "file_path": "app.py",
      "line_number": 5,
      "rule_id": "SAST-TAINT-001",
      "rule_name": "Fluxo de Dados Não Sanitizado",
      "severity": "critical",
      "cwe_id": "CWE-20",
      "title": "Tainted flow to os.system",
      "description": "Input inseguro atinge a função 'os.system' sem sanitização prévia.",
      "code_snippet": "cmd -> os.system()",
      "language": "python"
    }
  ],
  "total": 2,
  "files": [
    {
      "file_path": "app.py",
      "language": "python",
      "lines_of_code": 5,
      "vulnerabilities_count": 2
    }
  ]
}
```

**Erros:**

| Código | Descrição |
|--------|-----------|
| `401` | API Key inválida ou ausente |
| `502` | Serviço Analyzer indisponível |
| `504` | Timeout do Analyzer |

---

## Scans de Repositório (Assíncrono)

### `POST /api/v1/scans`

Registra um novo scan de repositório Git e enfileira a análise assíncrona.

**Request:**
```json
{
  "repository_url": "https://github.com/exemplo/repositorio",
  "branch": "main",
  "language": "python"
}
```

> Python é a linguagem primária analisada. JavaScript/TypeScript e Java são experimentais: parsing disponível não implica regras SAST completas. `language` também pode selecionar essas linguagens ou `"auto"` (detecção por extensão).

**Response 201:**
```json
{
  "id": 42,
  "repository_url": "https://github.com/exemplo/repositorio",
  "branch": "main",
  "language": "python",
  "status": "pending",
  "celery_task_id": "d4c8f2a1-1234-5678-abcd-ef0123456789",
  "total_files": null,
  "total_vulnerabilities": null,
  "created_at": "2024-01-25T10:30:00Z",
  "updated_at": "2024-01-25T10:30:00Z"
}
```

---

### `GET /api/v1/scans`

Lista todos os scans com paginação e filtros opcionais.

**Query Parameters:**

| Parâmetro | Tipo | Padrão | Descrição |
|-----------|------|--------|-----------|
| `page` | int | 1 | Número da página |
| `page_size` | int | 20 | Itens por página (máx. 200) |
| `status` | string | — | Filtrar por status: `pending`, `running`, `completed`, `failed`, `cancelled` |
| `repository_url` | string | — | Filtrar por URL (busca parcial) |

**Response 200:**
```json
{
  "items": [
    {
      "id": 42,
      "repository_url": "https://github.com/exemplo/repo",
      "branch": "main",
      "language": "python",
      "status": "completed",
      "total_files": 15,
      "total_vulnerabilities": 7,
      "created_at": "2024-01-25T10:30:00Z",
      "updated_at": "2024-01-25T10:35:22Z"
    }
  ],
  "total": 1,
  "page": 1,
  "page_size": 20,
  "pages": 1
}
```

---

### `GET /api/v1/scans/{id}`

Retorna os detalhes de um scan específico.

**Path Parameters:** `id` (int) — ID do scan

**Response 200:** Mesmo schema de item acima.
**Response 404:** `{"detail": "Scan with id=99 not found."}`

---

### `DELETE /api/v1/scans/{id}`

Remove permanentemente um scan e todas as vulnerabilidades associadas.

**Response 200:**
```json
{"detail": "Scan deleted successfully"}
```

---

### `POST /api/v1/scans/{id}/cancel`

Cancela um scan em estado `pending` ou `running`.

**Response 200:** Scan atualizado com `status: "cancelled"`.
**Response 409:** `{"detail": "Cannot cancel a scan with status 'completed'."}`

---

## Vulnerabilidades

### `GET /api/v1/vulnerabilities`

Lista vulnerabilidades com filtros avançados.

**Query Parameters:**

| Parâmetro | Tipo | Descrição |
|-----------|------|-----------|
| `page` | int | Página (padrão: 1) |
| `page_size` | int | Tamanho (padrão: 20, máx: 200) |
| `scan_id` | int | Filtrar por scan |
| `severity` | string | `critical`, `high`, `medium`, `low`, `info` |
| `file_path` | string | Filtrar por caminho (parcial) |
| `rule_id` | string | Filtrar por ID de regra (ex: `SAST-001`) |
| `suppressed` | bool | `true` ou `false` |

**Response 200:**
```json
{
  "items": [
    {
      "id": 101,
      "scan_id": 42,
      "file_path": "src/auth.py",
      "line_number": 87,
      "column": 4,
      "rule_id": "SAST-001",
      "rule_name": "SQL Injection via f-string",
      "severity": "critical",
      "cwe_id": "CWE-89",
      "title": "SQL Injection via f-string",
      "description": "Interpolação de variável não sanitizada em query SQL.",
      "code_snippet": "cursor.execute(f\"SELECT * FROM users WHERE id = {user_id}\")",
      "ai_suggestion": null,
      "ai_severity": null,
      "ai_triage": null,
      "confidence": null,
      "language": "python",
      "suppressed": false,
      "suppressed_reason": null,
      "created_at": "2024-01-25T10:35:22Z"
    }
  ],
  "total": 1,
  "page": 1,
  "page_size": 20,
  "pages": 1
}
```

---

### `PATCH /api/v1/vulnerabilities/{id}/suppress`

Marca uma vulnerabilidade como suprimida (falso positivo aceito) ou restaura.

**Request:**
```json
{
  "suppressed": true,
  "reason": "Testado manualmente — variável validada antes do uso."
}
```

**Response 200:** Vulnerabilidade atualizada.

---

## Estatísticas

### `GET /api/v1/stats/summary`

Resumo geral da plataforma para o widget principal do dashboard.

**Response 200:**
```json
{
  "total_scans": 23,
  "total_vulnerabilities": 154,
  "active_scans": 2,
  "failed_scans": 1,
  "critical_count": 18,
  "files_analyzed": 312,
  "scans_this_week": 5,
  "severity_breakdown": [
    {"severity": "critical", "count": 18},
    {"severity": "high", "count": 41},
    {"severity": "medium", "count": 62},
    {"severity": "low", "count": 28},
    {"severity": "info", "count": 5}
  ]
}
```

---

### `GET /api/v1/stats/trends`

Contagem de novas vulnerabilidades por dia nos últimos N dias.

**Query Parameters:** `days` (int, padrão: 30, máx: 365)

**Response 200:**
```json
{
  "data": [
    {"date": "2024-01-20", "count": 0},
    {"date": "2024-01-21", "count": 12},
    {"date": "2024-01-22", "count": 3}
  ],
  "period_days": 30
}
```

---

### `GET /api/v1/stats/top-files`

Top arquivos com mais vulnerabilidades (útil para priorizar refatoração).

**Query Parameters:** `limit` (int, padrão: 10, máx: 100)

**Response 200:**
```json
{
  "items": [
    {"file_path": "src/auth.py", "vulnerabilities_count": 8, "scan_id": 42},
    {"file_path": "src/utils.py", "vulnerabilities_count": 5, "scan_id": 42}
  ]
}
```

---

### `GET /api/v1/stats/by-rule`

Vulnerabilidades agrupadas por regra de detecção.

**Response 200:**
```json
{
  "items": [
    {
      "rule_id": "SAST-001",
      "rule_name": "SQL Injection via f-string",
      "count": 23,
      "severities": [
        {"severity": "critical", "count": 23}
      ]
    }
  ]
}
```

---

### `GET /api/v1/stats/severity-distribution`

Dados para gráfico de pizza/donut da distribuição por severidade.

**Response 200:**
```json
{
  "labels": ["Critical", "High", "Medium", "Low"],
  "values": [18, 41, 62, 28],
  "colors": ["#dc2626", "#ea580c", "#d97706", "#2563eb"]
}
```

---

## Códigos de Erro

| Código | Significado |
|--------|-------------|
| `400` | Requisição malformada (dados inválidos) |
| `401` | Não autenticado — API Key ausente ou inválida |
| `404` | Recurso não encontrado |
| `409` | Conflito de estado (ex: cancelar scan já concluído) |
| `422` | Erro de validação do corpo da requisição (Pydantic) |
| `500` | Erro interno do servidor |
| `502` | Serviço downstream (Analyzer ou AI) retornou erro |
| `504` | Timeout aguardando serviço downstream |

# Arquitetura da Plataforma SAST — C4 Model

Este documento descreve a arquitetura da Plataforma SAST & DevSecOps em três níveis do **C4 Model**: System Context, Container Diagram e Component Diagram.

---

## Nível 1 — System Context

> Quem usa o sistema e com quais sistemas externos ele se integra?

```mermaid
C4Context
    title System Context — Plataforma SAST & DevSecOps

    Person(dev, "Desenvolvedor / Engenheiro de Segurança", "Submete código para análise, consulta findings e aplica remediações.")
    Person(ci, "Pipeline CI/CD", "GitHub Actions / GitLab CI que invoca a plataforma como Security Gate.")

    System(sast, "Plataforma SAST & DevSecOps", "Detecta vulnerabilidades de segurança via análise estática (AST + Taint), enriquece com IA generativa e expõe métricas via dashboard.")

    System_Ext(github, "GitHub / GitLab", "Repositório de código-fonte. Fornece webhooks de Pull Request.")
    System_Ext(ollama_ext, "Ollama (Llama 3)", "LLM local rodando em container. Classifica falsos positivos e sugere remediações.")

    Rel(dev, sast, "Consulta dashboard, inicia scans, revisa findings", "HTTPS / REST")
    Rel(ci, sast, "Envia código, recebe resultado (pass/fail)", "REST API (curl/webhook)")
    Rel(sast, github, "Clona repositórios para análise", "HTTPS / Git")
    Rel(sast, ollama_ext, "Solicita classificação e remediação", "HTTP / JSON")
```

---

## Nível 2 — Container Diagram

> Quais são os principais executáveis / processos e como eles se comunicam?

```mermaid
C4Container
    title Container Diagram — Plataforma SAST & DevSecOps

    Person(dev, "Desenvolvedor / Engenheiro de Seg.")
    Person(ci, "Pipeline CI/CD")

    Container_Boundary(plataforma, "Plataforma SAST") {
        Container(dashboard, "Dashboard React", "React 18 + Vite + Tailwind", "Interface web para visualização de scans, vulnerabilidades e métricas de segurança. Porta 3000.")
        Container(api, "API REST", "Python 3.11 + FastAPI + SQLAlchemy", "Ponto de entrada principal. Gerencia scans, vulnerabilidades e estatísticas. Porta 8000.")
        Container(worker, "Celery Worker", "Python 3.11 + Celery", "Executa tarefas de scan de forma assíncrona, consome fila Redis.")
        Container(analyzer, "Analyzer (SAST Engine)", "Python 3.11 + FastAPI", "Parser AST + Rules Engine + Taint Analyzer. Porta interna 8002.")
        Container(ai_svc, "AI Service", "Python 3.11 + FastAPI + httpx", "Proxy para o Ollama, gerencia prompts e respostas do LLM. Porta interna 8003.")
        ContainerDb(db, "PostgreSQL 15", "PostgreSQL", "Persiste scans, vulnerabilidades e arquivos analisados.")
        ContainerDb(redis, "Redis 7", "Redis", "Broker de mensagens para o Celery. Cache de sessão.")
        Container(ollama, "Ollama", "Servidor LLM (Docker)", "Serve o modelo Llama 3 localmente. Porta 11434.")
    }

    Rel(dev, dashboard, "Acessa via browser", "HTTPS")
    Rel(ci, api, "POST /scan/file ou /scans", "REST/JSON")
    Rel(dashboard, api, "REST API calls", "HTTP/JSON")
    Rel(api, db, "CRUD via SQLAlchemy (async)", "TCP/SQL")
    Rel(api, redis, "Enfileira tarefas Celery", "TCP/Redis protocol")
    Rel(worker, redis, "Consome fila de tarefas", "TCP/Redis protocol")
    Rel(worker, analyzer, "POST /analyze", "HTTP/JSON")
    Rel(worker, ai_svc, "POST /ai/batch-analyze", "HTTP/JSON")
    Rel(worker, db, "Persiste findings", "TCP/SQL")
    Rel(ai_svc, ollama, "Chama modelo LLM", "HTTP/JSON")
```

---

## Nível 3 — Component Diagram: Serviço Analyzer

> Quais são os componentes internos do serviço de análise e como eles interagem?

```mermaid
C4Component
    title Component Diagram — Analyzer (SAST Engine)

    Container_Boundary(analyzer_svc, "Analyzer Service (porta 8002)") {
        Component(api_layer, "FastAPI Router (/analyze)", "FastAPI", "Recebe requisições HTTP com código-fonte e delega para o Scanner.")
        Component(scanner, "SASTScanner", "Python class", "Orquestra o pipeline: Parser → Rules Engine → Taint Analyzer. Suporta scan de snippet e de repositório Git.")
        Component(parser, "ASTParser", "Python ast / tree-sitter", "Python usa ast nativo. JavaScript/TypeScript e Java têm parsing experimental; isso não significa paridade de regras SAST.")
        Component(rules, "RulesEngine", "Python class + dataclasses", "Aplica regras heurísticas principalmente para Python; não constitui cobertura completa das linguagens.")
        Component(taint, "TaintAnalyzer", "Python ast", "Análise experimental e limitada a Python: fluxo aproximado em instruções, coleções comuns e chamadas no mesmo arquivo.")
    }

    Container(worker_ext, "Celery Worker", "chamador externo")
    ContainerDb(db_ext, "PostgreSQL", "resultados persistidos pelo Worker")

    Rel(worker_ext, api_layer, "POST /analyze {code, filename, language}", "HTTP/JSON")
    Rel(api_layer, scanner, "scan_snippet(code, lang, filename)")
    Rel(scanner, parser, "parse_code(code, language)")
    Rel(scanner, rules, "check_all(ast_data, code, language)")
    Rel(scanner, taint, "analyze(ast_data, code)")
    Rel(api_layer, worker_ext, "Retorna {vulnerabilities, taint_flows, files}", "HTTP/JSON")
```

---

## Fluxo de Dados de um Scan

```mermaid
sequenceDiagram
    participant CI as Pipeline CI/CD
    participant API as FastAPI (8000)
    participant Redis as Redis Broker
    participant Worker as Celery Worker
    participant Analyzer as Analyzer (8002)
    participant AI as AI Service (8003)
    participant Ollama as Ollama (11434)
    participant DB as PostgreSQL

    CI->>API: POST /api/v1/scans {repo_url, branch, language}
    API->>DB: INSERT scan (status=pending)
    API->>Redis: Enfileira task run_scan(scan_id)
    API-->>CI: 201 Created {scan_id, status: pending}

    Redis->>Worker: Consome task
    Worker->>Analyzer: POST /analyze {code, filename, language}
    Analyzer-->>Worker: {vulnerabilities, taint_flows, files}
    Worker->>AI: POST /ai/analyze {finding, code_snippet}
    AI->>Ollama: Prompt LLM
    Ollama-->>AI: {is_false_positive, remediation}
    AI-->>Worker: {enhanced_findings}
    Worker->>DB: INSERT vulnerabilities, UPDATE scan (status=completed)

    CI->>API: GET /api/v1/scans/{id}
    API-->>CI: {status: completed, total_vulnerabilities: N}
```

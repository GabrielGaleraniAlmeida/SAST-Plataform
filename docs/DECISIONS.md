# Architecture Decision Records (ADRs)

Este documento registra as principais decisões de arquitetura tomadas durante o desenvolvimento da Plataforma SAST & DevSecOps, seguindo o formato [MADR](https://adr.github.io/madr/).

---

## ADR-001: Processamento Assíncrono com Celery + Redis

**Status:** Aceito
**Data:** 2024-01-15
**Decisores:** Equipe de Engenharia

### Contexto

A análise SAST de repositórios grandes pode levar de segundos a vários minutos dependendo do tamanho do código, número de arquivos e se o modelo de IA é invocado. Uma requisição HTTP síncrona com esse tempo de espera:
- Causaria timeouts no cliente (CI/CD pipelines têm limites de 30-60 segundos por padrão)
- Bloquearia threads/workers da API durante toda a análise
- Impossibilitaria múltiplos scans concorrentes sem degradação severa

### Decisão

Adotamos **Celery** como framework de processamento de tarefas assíncronas com **Redis** como broker de mensagens.

- A API registra o scan no banco, enfileira uma task Celery e retorna `201 Created` imediatamente
- O cliente consulta `GET /scans/{id}` periodicamente (polling) ou via webhook para obter o status
- O Worker Celery consome a fila, executa o scan e atualiza o banco com os resultados

### Alternativas Consideradas

| Alternativa | Prós | Contras |
|------------|------|---------|
| **FastAPI Background Tasks** | Sem dependência extra, simples | Perde trabalho se o processo morrer; sem retry; sem escalabilidade horizontal |
| **RQ (Redis Queue)** | Mais simples que Celery | Menos recursos (sem beat scheduler, menos monitoramento) |
| **Dramatiq** | API mais Pythônica | Menos adotado, documentação menor |
| **Celery + Redis** ✅ | Maduro, escalável, retry automático, monitoramento (Flower) | Maior complexidade operacional |

### Consequências

- ✅ Scans podem escalar horizontalmente adicionando mais workers
- ✅ Tarefas com falha são retentadas automaticamente
- ✅ Redis serve tanto como broker quanto para cache futuro
- ⚠️ Adiciona dois containers ao stack (Redis + Celery Worker)
- ⚠️ O cliente precisa implementar polling para verificar conclusão

---

## ADR-002: IA Generativa Local com Ollama + Llama 3

**Status:** Aceito
**Data:** 2024-01-20
**Decisores:** Equipe de Engenharia

### Contexto

A plataforma usa IA generativa para:
1. Sugerir classificação de severidade e triagem de falso positivo
2. Sugerir remediações de código para revisão humana

A triagem da IA é registrada como metadado auditável e não suprime findings automaticamente.

Precisamos de uma solução que seja confiável, econômica e adequada a ambientes corporativos com restrições de privacidade de código.

### Decisão

Adotamos **Ollama** como runtime de LLM local com o modelo **Llama 3** (Meta) como padrão.

- Todo processamento ocorre localmente, dentro do Docker Compose, sem envio de código para APIs externas
- O modelo é baixado uma única vez via `ollama pull` no container `ollama_model`
- O modelo pode ser trocado via variável de ambiente `OLLAMA_MODEL` (ex: `codellama`, `mistral`)

### Alternativas Consideradas

| Alternativa | Prós | Contras |
|------------|------|---------|
| **OpenAI GPT-4** | Excelente qualidade, API madura | Custo por token (em produção pode ser caro), código do cliente vai para servidores externos |
| **Google Gemini API** | Alta qualidade | Mesmos problemas de privacidade e custo |
| **AWS Bedrock** | Privacidade dentro da AWS | Custo, lock-in de nuvem, complexidade de setup |
| **Ollama + Llama 3** ✅ | Gratuito, privado, sem dependência de rede externa | Requer GPU/RAM significativa; qualidade inferior a GPT-4 |
| **llama.cpp (direto)** | Mais leve | API menos amigável, sem suporte a múltiplos modelos facilmente |

### Consequências

- ✅ Zero custo de API; adequado para demonstrações offline
- ✅ Código analisado nunca sai do ambiente local (compliance)
- ✅ Modelo configurável sem alterar código
- ⚠️ Llama 3 (8B) requer ~8GB RAM; modelo 70B requer GPU dedicada
- ⚠️ Qualidade das sugestões inferior ao GPT-4 para código complexo
- ⚠️ Primeira inicialização lenta (download do modelo ~4GB)

---

## ADR-003: Parser Python via `ast` Nativo vs Tree-sitter

**Status:** Aceito
**Data:** 2024-01-25
**Decisores:** Equipe de Engenharia

### Contexto

O núcleo da plataforma SAST depende de parsear código-fonte em uma AST (Abstract Syntax Tree) estruturada para aplicar regras de segurança e taint analysis. Python é a linguagem primária de suporte, com planos de expandir para JavaScript e Java.

### Decisão

Adotamos a estratégia híbrida:

- **Python:** Usar o módulo `ast` da **biblioteca padrão do Python** (sem dependência extra)
- **JavaScript / Java:** Há parsing experimental com **tree-sitter** e gramáticas específicas quando disponíveis. Isso não representa regras SAST completas nem paridade de análise com Python.

### Alternativas Consideradas

| Alternativa | Prós | Contras |
|------------|------|---------|
| **`ast` nativo (apenas Python)** ✅ | Zero dependência, API rica, acesso a `lineno`/`col_offset`, suporte completo a todas features Python 3.x | Apenas Python |
| **tree-sitter (universal)** | Suporte a 100+ linguagens, incremental | Dependência C com binding Python, setup mais complexo, AST menos semântica que `ast` nativo |
| **Semgrep como biblioteca** | Regras ricas com padrões | Licença restrita para uso embutido, overhead |
| **Libra/Joern** | Análise de bytecode, inter-procedural real | Requer JVM, complexidade operacional alta |

### Consequências

- ✅ Parser Python extremamente robusto e sem overhead de instalação
- ✅ Taint Analysis tira proveito da semântica rica do `ast` (tipos de nós, posições exatas)
- ✅ Infraestrutura pronta para tree-sitter: `ASTParser.parse_javascript()` já existe
- ⚠️ JavaScript/Java são experimentais; o parsing não é evidência de análise SAST completa
- ⚠️ Taint inter-procedural completo (entre arquivos) não é suportado pelo `ast` nativo — exigiria um grafo de chamadas completo

---

## Histórico de Decisões

| ADR | Título | Status | Data |
|-----|--------|--------|------|
| ADR-001 | Celery + Redis para processamento assíncrono | Aceito | 2024-01-15 |
| ADR-002 | Ollama/Llama3 para IA local | Aceito | 2024-01-20 |
| ADR-003 | Python `ast` vs tree-sitter | Aceito | 2024-01-25 |

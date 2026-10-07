# PROJETO INTEGRADOR: PLATAFORMA SAST & DEVSECOPS
**Engenharia de Software - 3º Ano**
*Atividade Prática de Curso | Prof. M.Sc Oerton Fernandes | 2026*

---

## SEGURANÇA PREVENTIVA COM SAST

### O CONCEITO DE SAST
* **Static Application Security Testing**: análise do código-fonte **sem execução**.
* Identifica vulnerabilidades estruturais, vazamento de segredos e falhas lógicas na raiz do desenvolvimento.

### A ESTRATÉGIA SHIFT-LEFT
* Traz a segurança para o início do SDLC, auditando cada commit automaticamente.
* Reduz drasticamente o custo de correção e evita que falhas críticas alcancem o ambiente de produção.

---

## OBJETIVOS E COMPETÊNCIAS

* **COMPILADORES & AST**: Uso de parsers para construir Árvores de Sintaxe Abstrata e realizar inspeção estrutural.
* **SEGURANÇA LÓGICA**: Mapeamento de vulnerabilidades CWE e padrões inseguros no OWASP Top 10.
* **IA & SEMÂNTICA**: Uso de LLMs para interpretar a intenção do código e sugerir correções automatizadas.
* **DEVSECOPS**: Implementação de Security Gates em pipelines CI/CD para proteção contínua.

---

## O DESAFIO SAST

* **PARSING MULTI-LINGUAGEM**: Construir um motor capaz de interpretar a estrutura de múltiplas linguagens através de ASTs robustas.
* **REGRAS E HEURÍSTICAS**: Aplicar verificações determinísticas e análise semântica para detectar falhas de segurança complexas.
* **REMEDIAÇÃO COM IA**: Integrar modelos de linguagem para fornecer sugestões de correção automáticas e contextuais.
* **ESCALABILIDADE**: Garantir performance através de uma arquitetura de microsserviços assíncronos e processamento em fila.

---

## ARQUITETURA E STACK SAST

| COMPONENTE | TECNOLOGIAS RECOMENDADAS |
| :--- | :--- |
| **Engine de Análise** | Tree-sitter, Python (AST), Bandit, Semgrep |
| **Módulo de IA** | Ollama (Llama 3), Hugging Face, LangChain |
| **Backend & API** | FastAPI, PostgreSQL, Redis / Celery |
| **DevSecOps** | Docker, GitHub Actions, GitLab CI |

---

## CP 1: FUNDAÇÃO E PARSERS

### FOCO DO PERÍODO
* Configuração do ambiente de desenvolvimento conteinerizado com Docker e definição da arquitetura base (C4 Model).
* Desenvolvimento do motor de Parsing: construção da Árvore de Sintaxe Abstrata (AST) para análise estrutural.
* Implementação de regras básicas para detecção de senhas hardcoded e funções perigosas (ex: `eval`).

### CHECKPOINT 1
- [x] Diagrama de Arquitetura Técnica
- [x] Repositório com Docker Compose
- [x] Parser de Código Funcional
- [x] Detecção de 3 Violações Iniciais

---

## CP 2: IA E ANÁLISE SEMÂNTICA

### FOCO DO PERÍODO
* **TAINT ANALYSIS**: Rastreamento de fluxo de dados para identificar se entradas não sanitizadas alcançam funções sensíveis (sinks).
* **INTELIGÊNCIA ARTIFICIAL**: Uso de LLMs locais (Ollama/Llama 3) para classificar severidade e reduzir falsos positivos em lógicas complexas.
* **SUGESTÕES DE CORREÇÃO**: Geração automatizada de blocos de código corrigidos (Remediation Advice) baseados na vulnerabilidade detectada.

### CHECKPOINT 2
- [x] Módulo de Taint Analysis
- [x] Integração com LLM Local
- [x] Sugestões de Remediação
- [x] Demo de varredura semântica

---

## SUGESTÕES DE DASHBOARDS

### SEVERIDADE E TENDÊNCIAS
* **Severidade**: Gráfico de distribuição (Ex: 55% Baixo, 25% Médio, 15% Alto, 5% Crítico).
* **Tendência de falhas**: Gráfico de linha mostrando a evolução de falhas ao longo das semanas.

### TOP 5 ARQUIVOS CRÍTICOS
1. `auth_controller.py`: 12 Falhas
2. `db_config.js`: 8 Falhas
3. `user_service.java`: 5 Falhas

### FALHAS DETECTADAS (BETA)
* **CVE-2014-3704 - SQL Injection (SQLi)**: O famoso "Drupalgeddon". Permitia que atacantes não autenticados enviassem comandos SQL maliciosos, resultando no controle total do banco de dados.
* **CVE-2020-11022 - Cross-Site Scripting (XSS)**: Uma falha no jQuery que permitia a execução de scripts maliciosos no navegador do usuário ao processar elementos HTML de fontes não confiáveis.
* **CVE-2020-13379 - Server-Side Request Forgery (SSRF)**: Falha no Grafana que permitia a um atacante forçar o servidor a fazer requisições para a rede interna, expondo serviços protegidos.
* **CVE-2021-41773 - Broken Access Control**: Uma falha de Path Traversal no servidor Apache que permitia acessar arquivos sensíveis fora da pasta raiz do servidor web.

---

## CP 3: DEVSECOPS E ENTREGA

### FOCO NA INTEGRAÇÃO
* Implementação de Security Gates em pipelines CI/CD (GitHub Actions) para bloqueio de Pull Requests inseguros.
* Desenvolvimento do Dashboard Executivo para visualização de por arquivo, linha e severidade.
* Refinamento da experiência do usuário e preparação da documentação técnica para a defesa final.

### CHECKPOINT 3 (FINAL)
- [x] Plataforma SAST 100% Funcional
- [x] Integração CI/CD com Security Gates
- [x] Dashboard e Relatórios Analíticos
- [x] Defesa Técnica e Documentação
* **ENTREGA FINAL DO PROJETO**

---

## CRITÉRIOS DE AVALIAÇÃO

| PESO | CRITÉRIO | EXCELÊNCIA (CONCEITO A) |
| :---: | :--- | :--- |
| **25%** | **ARQUITETURA** | Uso eficiente de AST/Parsers, modularidade orientada a serviços e containerização Docker robusta. |
| **30%** | **ROBUSTEZ SAST** | Precisão na detecção de vulnerabilidades estáticas, eficiência no parsing e baixo índice de falsos positivos. |
| **20%** | **INOVAÇÃO IA** | Uso avançado de LLMs locais para análise semântica precisa e geração de correções de código úteis. |
| **15%** | **DEVSECOPS** | Automação fluida em pipelines CI/CD com Security Gates funcionais e relatórios claros. |
| **10%** | **DEFESA** | Clareza na apresentação técnica e profundidade na análise crítica dos resultados obtidos. |

---

## ÉTICA E PRÓXIMOS PASSOS

### RESPONSABILIDADE ÉTICA
* A análise de código deve respeitar a propriedade intelectual e a privacidade do código-fonte. Utilize apenas repositórios autorizados ou de código aberto para testes.
* O objetivo é a melhoria contínua e o auxílio ao desenvolvedor, garantindo a integridade do ecossistema de software.

### INÍCIO DO PROJETO
* Formação de grupos (4-5 integrantes)
* Escolha da linguagem alvo (Python/JS/Java)
* Primeiro Check point: CP1

---
*2026 | Prof.M.Sc Oerton Fernandes | Todos os Direitos Reservados® | Proibido Reprodução*

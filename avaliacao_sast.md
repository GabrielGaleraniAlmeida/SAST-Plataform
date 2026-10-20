# Avaliação técnica atual — Plataforma SAST & DevSecOps

Esta avaliação descreve o código e a documentação deste diretório. Não é uma nota acadêmica, auditoria independente nem certificação de segurança. Resultados de execução devem ser consultados no histórico real dos comandos e dos workflows; não há screenshots de dashboard anexadas como evidência.

## Estado implementado

| Área | Estado verificável no código |
|---|---|
| Linguagem analisada | Python é a linguagem primária: parsing com `ast` e conjunto heurístico de regras. |
| Taint analysis | Análise aproximada por escopo Python, com fontes/sinks selecionadas, atribuições, expressões/coleções, algumas mutações e chamadas locais limitadas. |
| Fluxos | Findings guardam fonte, sink, linhas, função, variável e cadeia aproximada; sanitizadores reconhecidos são contextuais e explícitos. |
| IA | Ollama pode classificar severidade e produzir triagem/remediação. Respostas inválidas e indisponibilidade usam fallback. A triagem é persistida como metadado auditável; não suprime findings automaticamente. |
| API e dashboard | A API persiste scans/findings e o dashboard exibe os resultados disponíveis; `POST /api/v1/scan/file` é síncrono e não persiste scan. |
| Configuração local | `.env.example` contém valores placeholders, `.env` é ignorado, e portas do Compose estão vinculadas a `127.0.0.1`. |
| CI | Testes/cobertura têm status bloqueante, relatório é publicado mesmo em falha e o job constrói os serviços configurados no Compose. |
| Security gates | Bandit, Semgrep, Trivy e auditoria de todos os manifests Python e do lockfile npm são obrigatórios no workflow; relatórios ausentes/inválidos ou falhas de execução falham o gate agregado. |

## Limitações técnicas

- O taint analyzer é uma aproximação AST de uma passagem, não análise completa de fluxo de controle. Não modela com precisão branches, loops, exceções, variáveis globais/closures, aliases, tipos ou mutações arbitrárias.
- A propagação interprocedural limita-se a chamadas simples no mesmo arquivo, argumentos posicionais/nomeados e retornos, com profundidade máxima configurada no código. Não resolve chamadas dinâmicas, métodos/objetos em geral, imports ou código externo.
- Coleções recebem propagação aproximada; destructuring, aliases e mutações complexas podem produzir falsos positivos ou falsos negativos. A lista de fontes, sinks e sanitizadores é incompleta.
- A marcação `is_sanitized` significa apenas que um sanitizador reconhecido foi visto em um contexto listado. Não constitui prova de segurança e não cobre todos os contextos semânticos de cada biblioteca.
- JavaScript/TypeScript e Java são experimentais. Tree-sitter pode produzir parsing, mas não há paridade de regras próprias nem taint analysis equivalente.
- O conjunto de casos conhecido é pequeno e sintético. Não mede eficácia em repositórios reais nem sustenta alegações amplas de precision/recall.
- A classificação de IA depende do modelo e do prompt, não é uma decisão determinística de segurança. Os testes cobrem contrato, parsing e fallback com respostas simuladas, não acurácia do LLM.
- Não há controles suficientes, auditoria operacional nem validação abrangente para declarar o sistema pronto para produção.
- A configuração Compose foi validada. A construção local das imagens e a migração/persistência em banco não foram verificadas porque o daemon Docker respondeu com erro de conexão.

## Melhorias ainda não comprovadas ou pendentes

- A aprovação dos workflows depende de suas execuções no GitHub. O ambiente local não substitui essa evidência.
- Nesta revisão, `make coverage` concluiu com **80 testes passando e 76,76% de cobertura reportada**, acima do gate configurado de 70%. Esse valor é o resultado medido pelo escopo `--cov=services` da suíte atual; não representa cobertura completa dos endpoints/serviços ainda não importados ou exercitados.
- O corpus SAST de taint mediu TP=3, FP=0, FN=0, TN=2 em cinco casos sintéticos. A triagem de IA não tem métrica medida: os casos de IA são ground truth documentado, e os testes de contrato usam respostas simuladas.
- As versões de dependências e os resultados dos scanners precisam ser revisados continuamente; um gate com limite não significa ausência de vulnerabilidades.
- A instalação/auditoria npm reportou **6 vulnerabilidades HIGH e 5 MODERATE** no dashboard; ainda não foram corrigidas. A execução do workflow DevSecOps completo não foi feita localmente.
- O corpus e a cobertura de integração não substituem testes em aplicações representativas, revisão manual ou avaliação independente.

Veja [`docs/VALIDATION.md`](docs/VALIDATION.md) para comandos de teste e definição dos casos rotulados.

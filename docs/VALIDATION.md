# Validação e casos conhecidos

## Executar testes e relatórios

Na raiz do projeto, com Python compatível e o ambiente virtual ativado:

```powershell
python -m pip install -r services/analyzer/requirements.txt
python -m pip install -r services/api/requirements.txt
python -m pip install -r services/ai/requirements.txt
python -m pip install -r requirements-test.txt
python -m pytest tests/ -v
python -m pytest tests/ -v --cov=services --cov-report=term-missing --cov-report=xml:reports/coverage/coverage.xml --cov-report=html:reports/coverage/html --cov-fail-under=70
```

O Makefile oferece `make test`, `make coverage` e `make lint`. A cobertura só passa se alcançar 70%; os relatórios HTML e XML são medidas da suíte executada, não estimativas de eficácia de segurança.

Frontend:

```powershell
Set-Location services/dashboard
npm ci
npm run lint
npm run build
```

Compose:

```powershell
Copy-Item .env.example .env
# Edite .env, substitua os placeholders e sincronize as senhas nos dois URLs do banco.
docker compose config --quiet
docker compose build
```

## Corpus SAST rotulado

`tests/fixtures/taint_cases.json` contém exemplos pequenos com rótulos esperados: fluxo direto para shell, propagação via variável e mutação de dicionário (positivos), `shlex.quote` em sink de shell (sem finding de taint no contexto listado) e variáveis locais independentes entre funções (negativo). `tests/test_security_benchmark.py` executa o pipeline real do scanner e contabiliza findings TP, FP, FN e TN; reproduza a saída com:

```powershell
python -m pytest tests/test_security_benchmark.py -q -s
```

Essas contagens referem-se apenas a esse corpus, que é sintético e muito pequeno. Não devem ser generalizadas como precisão/recall do produto. Testes adicionais em `tests/test_taint_analysis.py` documentam fluxo por argumentos/retorno, mutação de lista/dicionário, sanitização genérica não confiável, chamada importada não resolvida e limite de profundidade.

## Casos de triagem por IA

`tests/fixtures/ai_triage_cases.json` registra exemplos rotulados de fluxo para shell, query SQL parametrizada e placeholder de credencial. Os rótulos são expectativas de avaliação dos exemplos, não resultados de IA. Para medir um modelo real, envie os mesmos findings para triagem, compare `is_false_positive` com `ground_truth_is_false_positive` e calcule TP/FP/FN/TN somente sobre respostas válidas; salve também modelo, versão/configuração e revisão humana. Respostas inválidas ou indisponibilidade devem ser reportadas como não avaliadas, nunca como acerto.

Os testes `tests/test_ai_analyzer.py` cobrem severidade, resposta de remediação, JSON inválido, fallback quando Ollama está indisponível e persistência da avaliação de falso positivo sem supressão. As respostas do modelo são simuladas: elas verificam o contrato e não medem a qualidade nem a taxa de falsos positivos/negativos de um modelo real.

Para uma avaliação de qualidade de IA, ainda é necessário executar um conjunto rotulado de findings em um modelo/configuração especificados e comparar a saída real com revisão humana. Nenhuma métrica de precisão/recall de IA é publicada enquanto essa avaliação não for executada. Um parecer de “falso positivo” da IA permanece consultável e exige ação humana explícita para suprimir o finding.

## Demonstração de scan

`POST /api/v1/scan/file` analisa um arquivo de forma síncrona; não cria registro de scan nem resultado persistido no dashboard. Para visualizar um scan persistido, crie um scan de repositório com `POST /api/v1/scans`, consulte o ID retornado até a conclusão e abra o scan no dashboard. A disponibilidade do Ollama altera apenas o enriquecimento da IA; não representa evidência de qualidade de classificação.

Não há neste documento saída de scan ou captura do dashboard, pois nenhuma evidência foi anexada à avaliação.

## Gates de segurança no CI

O workflow DevSecOps exige Bandit, Semgrep, Trivy para as imagens de aplicação construídas pelo Compose, `pip-audit` para cada `requirements.txt` dos serviços e o `npm audit` do dashboard usando seu lockfile. Scanner que falha, relatório ausente/inválido ou relatório acima do limite falha o gate; relatórios são publicados em artefatos e o PR recebe resumo. Limites agregados atuais: zero CRITICAL e até 10 HIGH. Como `pip-audit` não fornece severidade consistente para todos os avisos, cada finding dele conta conservadoramente como HIGH. Os scanners desta pipeline são obrigatórios; integração externa de API SAST não é tratada como scanner opcional aprovado.

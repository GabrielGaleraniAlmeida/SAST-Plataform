# Plataforma SAST & DevSecOps

Bem-vindo à plataforma **SAST (Static Application Security Testing)** open-source! Esta ferramenta detecta vulnerabilidades de segurança, credenciais expostas e falhas de fluxo de dados (Taint Analysis) usando análise estática profunda (AST) e IA Generativa local para remediação.

## Arquitetura C4 Model
Veja a pasta `/docs` para os diagramas de arquitetura completos.

## Funcionalidades
- **Parser Multi-Linguagem:** AST para Python (atualmente) e infraestrutura pronta para Java e JS via Tree-sitter.
- **Motor SAST Heurístico:** 15 regras nativas de segurança mapeadas para as top-vulnerabilidades (OWASP, CWE).
- **Taint Analysis:** Rastreamento do fluxo de informações não confiáveis até pontos de execução perigosos.
- **Integração com LLM:** Ollama (Llama 3) classifica falsos positivos e sugere remediações diretas no código.
- **Dashboard React:** Interface de visualização para engenheiros e gerentes.
- **DevSecOps nativo:** Pronto para GitHub Actions com Security Gates em pull requests.

## Quick Start (Docker Compose)
Para iniciar toda a arquitetura de microsserviços localmente:

```bash
make up
# ou
docker compose up -d --build --wait
```
Na primeira inicialização, o Compose baixa o modelo Ollama configurado (`llama3` por padrão); isso pode levar alguns minutos e requer espaço em disco. O serviço de IA só inicia depois que o modelo estiver disponível. Para trocar o modelo, defina `OLLAMA_MODEL` antes de iniciar.

- **API:** `http://localhost:8000/docs`
- **Dashboard:** `http://localhost:3000`

Em implantações com o dashboard em outra origem, configure `CORS_ORIGINS` como uma lista JSON,
por exemplo `["https://dashboard.example.com"]`. Por padrão, a API permite apenas as origens
locais usadas no desenvolvimento.

## Como Iniciar um Scan
Via API REST:
```bash
curl -X POST http://localhost:8000/api/v1/scans \
     -H "Content-Type: application/json" \
     -d '{"repository_url": "https://github.com/exemplo/repo", "branch": "main", "language": "python"}'
```

Para analisar um arquivo diretamente (como no passo `Custom SAST API` do CI):
```bash
curl -X POST http://localhost:8000/api/v1/scan/file \
     -H "Content-Type: application/json" \
     -d '{"filename":"app.py","content":"cursor.execute(f\\"SELECT * FROM users WHERE id = {user_id}\\")","language":"python"}'
```
O endpoint retorna `findings`, `total` e os arquivos analisados. A IA fica pronta quando
`http://localhost:8001/ai/health` responde `healthy`; essa checagem também confirma que o
modelo configurado está instalado no Ollama.

Desenvolvido para o Projeto Integrador de Engenharia de Software.

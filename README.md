# Agente de segurança da cadeia de software

CLI local para analisar dependências Python/Node.js, imagens Docker existentes, SBOMs e GitHub Actions. Produz evidências, relatórios em português e patches para revisão humana. A análise funciona sem IA; explicações por Ollama local são opcionais.

## Instalação

Ambiente validado: Linux x86_64, Python 3.11 ou superior e Git para os testes de aplicação de patches.

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
python -m pip install --no-build-isolation --no-deps -e .
python scripts/install_scanners.py
export PATH="$PWD/.tools/bin:$PATH"
sc-agent --help
```

O instalador baixa **Trivy 0.75.0** e **zizmor 1.30.1** de seus releases oficiais e confere SHA-256 fixado no código antes de instalar os executáveis. A CLI exige essas versões, pois parsers e patches foram validados com elas. As bases do Trivy continuam sendo atualizadas: fixar a versão do executável não congela os avisos de vulnerabilidades. Não há instalação automática de scanners, pacotes do alvo ou modelos durante uma análise.

## Uso

```sh
# O diretório de saída precisa ser novo ou vazio.
sc-agent scan --repo /caminho/projeto --out security-report

# Alvos combinados; --image e --sbom podem aparecer várias vezes.
sc-agent scan --repo /caminho/projeto \
  --image alpine:3.18 \
  --sbom inventario.cdx.json --sbom inventario.spdx.json \
  --out /tmp/analise-completa

# Bloqueio explícito por severidade.
sc-agent scan --repo /caminho/projeto --fail-on high --out /tmp/analise-ci

# Demonstração com fixtures intencionalmente vulneráveis.
sc-agent scan --repo tests/fixtures/repo --out /tmp/analise-exemplo
```

| Saída | Significado |
| --- | --- |
| `0` | Análise concluída; política não bloqueou. Pode haver vulnerabilidades. |
| `1` | Análise concluída com achados no limite de `--fail-on` ou acima. |
| `2` | Erro operacional, entrada inválida ou cobertura incompleta. Tem precedência sobre `1`. |

`--fail-on` aceita `none` (padrão), `low`, `medium`, `high` e `critical`. Achados `UNKNOWN` e `INFORMATIONAL` permanecem visíveis, sem satisfazer um limite de severidade conhecida. IA indisponível ou patch não validado gera aviso; não invalida uma análise determinística concluída.

Uma falha em um alvo não impede os demais. Sempre que o diretório de saída puder ser criado, falhas dos scanners são registradas nos relatórios. Erros de argumentos e de acesso ao diretório de saída retornam `2` sem sobrescrever arquivos existentes.

## Cobertura e limites

| Alvo | Cobertura validada |
| --- | --- |
| Python | `requirements.txt` com versões exatas; `uv.lock`, incluindo grupos de desenvolvimento. |
| Node.js | `package-lock.json` v2/v3, incluindo dependências de desenvolvimento e workspaces com lockfile ancestral. |
| Docker | Pacotes instalados, vulnerabilidades conhecidas, segredos e configurações da imagem; regras de Dockerfile no repositório. |
| SBOM | CycloneDX JSON 1.4–1.6 e SPDX JSON 2.2/2.3; vulnerabilidades dos componentes identificados. |
| Pipelines | Workflows e definições locais de actions; zizmor offline com persona `auditor`. |

Manifestos sem lockfile ou versões exatas, arquivos não interpretados e componentes de SBOM não reconhecidos produzem cobertura incompleta. `requirements.txt` precisa conter dependências transitivas resolvidas para cobri-las: o agente não instala pacotes para descobri-las. Um SBOM pode omitir dependências ou metadados, e sua assinatura/completude/correspondência com a imagem não é verificada. A persona `auditor` inclui achados de menor confiança, que devem ser revisados.

As cópias de repositórios excluem `.git`, `.venv`, `venv`, `node_modules`, `__pycache__`, `.pytest_cache`, `.tools` e a pasta de saída. Links simbólicos, arquivos especiais e arquivos acima de 16 MiB não são copiados e tornam a cobertura incompleta. A cópia aceita até 512 MiB; SBOMs até 16 MiB; saída JSON de scanner até 64 MiB. Cada subprocesso tem timeout de 300 segundos. Configurações, supressões e comentários de ignore dos scanners no repositório não são aceitos; a análise usa sua própria política explícita.

Imagens podem vir do Docker local ou de registry. Nenhuma imagem é construída ou executada. Bases, regras do Trivy e imagens de registry podem exigir acesso à rede; `--offline-scan` evita consultas para resolver dependências, mas não impede essas atualizações. Credenciais de registry podem usar o Docker configurado ou `TRIVY_USERNAME`, `TRIVY_PASSWORD`, `TRIVY_REGISTRY_TOKEN`; não passe credenciais na referência da imagem. Tokens GitHub e variáveis de configuração dos scanners não são herdados pelos subprocessos.

## Relatórios e patches

`report.json` tem `schema_version: 1`, data UTC, estado por alvo, versões das ferramentas e metadados disponíveis da base. Cada achado tem ID estável, regra/CVE, categoria, severidade original, evidência, recomendação e ocorrências com alvo, caminho e linha quando disponível. Duplicatas são agrupadas preservando as localizações e a maior severidade informada. `report.md` apresenta os mesmos resultados para revisão.

`patches/*.patch` contém somente propostas reanalisadas:

- Python: arquivos `requirements.txt` inteiramente compostos por pins simples `pacote==versão` e comentários. Cada aviso do pacote deve indicar uma única versão corrigida; usa-se a maior delas e exige-se a ausência dos avisos afetados e de novos achados na reanálise. Ranges, extras, hashes, markers, inclusões, pins duplicados e versões ambíguas recebem apenas orientação.
- Workflows: somente correções que o zizmor classifica como `safe`, geradas em outra cópia temporária e reanalisadas. Alterações sem redução comprovada dos achados ou com novos achados são descartadas. Várias regras, incluindo pinagem de actions, exigem intervenção manual.
- npm/uv, Docker e SBOMs: instruções de correção na origem; nenhum lockfile é regenerado.

Os arquivos originais nunca recebem os patches. Para revisar e aplicar **você mesmo**, a partir da raiz do repositório analisado:

```sh
cat /caminho/relatorio/patches/001.patch
git apply --check /caminho/relatorio/patches/001.patch
git apply /caminho/relatorio/patches/001.patch
# Execute os testes funcionais do projeto e analise novamente.
```

Uma correção de CVE pode ser incompatível com sua aplicação. Reanálise de segurança não substitui testes funcionais. Valores de segredos detectados são removidos dos relatórios; arquivos com segredos detectados e diffs que contenham esses valores não recebem patches. Saídas brutas e stderr dos scanners não são persistidos. Achados ainda revelam inventário e caminhos internos: revise os relatórios antes de compartilhá-los.

## Ollama opcional

Execute um servidor Ollama local com um modelo já instalado. Configure `OLLAMA_NO_CLOUD=1` no servidor para desabilitar recursos de nuvem. O agente consulta `/api/show` antes de enviar evidências e recusa modelos remotos, aliases remotos e nomes com `cloud`. Ele não baixa modelos.

```sh
sc-agent scan --repo /caminho/projeto --ai-model SEU_MODELO_LOCAL --out /tmp/analise-com-ia
```

O endpoint é fixo em `http://localhost:11434`, sem proxy ou redirecionamentos. A IA recebe apenas identificadores e fatos normalizados/sanitizados, sem arquivos-fonte, localizações privadas ou valores de segredos. As explicações são separadas e marcadas como não verificadas; nunca alteram achados, severidades, política do CI ou patches. Respostas com IDs inventados, campos extras ou formato inválido são descartadas. Os primeiros 50 achados por severidade são explicados em lotes de dez, com timeout de 60 segundos por lote; o relatório inclui todos os achados.

## Testes e CI

```sh
python -m pytest                     # Fixtures gravadas, sem rede e sem scanners
python -m pytest -m integration      # Scanners reais; exige instalação e acesso às bases/registry
```

A suíte cobre os quatro tipos de alvo, dependências de desenvolvimento, ambos os SBOMs, falhas operacionais, cobertura ausente, aplicação de patches em cópias, sigilo dos segredos detectados e isolamento da IA. As credenciais nas fixtures são sintéticas. Os testes de integração são ignorados se os scanners estiverem ausentes; instale-os para executar a validação completa.

O workflow de GitHub Actions instala as versões fixadas, executa ambas as suítes e analisa este projeto com `--fail-on none`. Tem permissões de leitura e publica artefatos mesmo após falhas, por sete dias. As fixtures vulneráveis fazem parte da análise do próprio projeto e geram achados intencionais. Para bloquear por severidade em seu projeto, adicione `--fail-on high` ao comando de análise.

Não há interface web, abertura de PRs, suporte validado a outros provedores de CI, atualização de lockfiles ou verificação de assinaturas/proveniência nesta versão. Ausência de achados não comprova ausência de riscos.

Referências: [Trivy](https://trivy.dev/docs/latest/guide/), [zizmor](https://docs.zizmor.sh/usage/), [Ollama](https://docs.ollama.com/capabilities/structured-outputs).
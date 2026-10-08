# Respostas dos scanners

Fixtures capturadas em 2026-10-08 com Trivy 0.75.0 e zizmor 1.30.1 sobre `../repo`, os dois SBOMs e a imagem Alpine por digest usada nos testes de integração.

Os JSONs preservam o formato dos scanners, com campos volumosos não utilizados removidos e caminhos do zizmor relativos ao repositório. `metadata.json` registra versões e datas da base. São dados de teste congelados: os testes unitários não consultam a rede. A credencial em `../repo/config.env` é sintética e não dá acesso a nenhuma conta; o Trivy a mascara na gravação.

Os testes de integração usam os executáveis reais e a base disponível no momento. Eles verificam comportamento e cobertura, sem fixar contagens de CVEs que mudam com a base.

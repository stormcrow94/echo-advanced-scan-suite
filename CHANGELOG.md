# Changelog

Todas as mudanças relevantes deste projeto. Formato inspirado em [Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/).

## [2026.11.1] - 2026-11-26

### Alterado
- O módulo `urls` passou a usar **[waymore](https://github.com/xnl-h4ck3r/waymore) 8.9** no lugar do **gau**.
  O gau ainda recebe commits, mas não tinha release desde outubro de 2024. O waymore é chamado em `-mode U`
  (só URLs, sem baixar respostas arquivadas), inclui subdomínios por padrão e não exige chaves de API.
  A saída continua em `urls.txt` para o relatório e o módulo `js`. Instalação via `pip`/`pipx` (versão em
  `scripts/versions.env`).

## [Revisão completa 2026.11] - 2026-11-25

Revisão geral do projeto: ferramentas atualizadas ou substituídas, bugs corrigidos, sistema de relatórios novo e
documentação reescrita.

### Adicionado
- **Relatórios PDF e JSON** gerados ao fim de cada execução (`report/echo_report.py`): idioma `en`, `pt-BR` ou
  ambos (`--report-lang`), formato `pdf|json|both|none` (`--format`), diretório (`--report-dir`) e personalização
  (`--report-title`, `--client`, `--author`, `--logo`). PDF com capa, sumário executivo, gráfico de severidade,
  módulos, achados detalhados, superfície de ataque e metodologia. JSON com schema estável documentado em
  `docs/REPORT_SCHEMA.md`. Exemplos com dados fictícios em `samples/`.
- Módulos novos: **`tls`** (tlsx: certificado expirado, autoassinado, nome divergente, não confiável, TLS < 1.2),
  **`crawl`** (katana com parsing de JS, robots e sitemap) e **crt.sh** como fonte de subdomínios.
- **Perfis** `passive`, `standard` (padrão) e `deep`; `--modules`, `--skip`, `--rate`, `--top-ports`,
  `--max-minutes`, `--dry-run`, `--check-deps`, `--install`, `--no-banner`, `--version`, `--help`.
- Banner ASCII na inicialização (desliga com `--no-banner`; cores desligam com `NO_COLOR` ou fora de terminal).
- `status.json` com o resultado de cada módulo (`ok`, `empty`, `skipped`, `failed`), duração e motivo.
- Detecção de hosts que "respondem em todas as portas" (firewall/WAF/tarpit) e de redes com proxy **fake-IP**
  (198.18.0.0/15): nesse caso os hosts são re-resolvidos via DNS-over-HTTPS e a varredura de portas é pulada,
  evitando milhares de falsos positivos.
- `scripts/install.sh` (Debian/Ubuntu e RHEL, amd64/arm64) e `scripts/versions.env` com versões fixadas, usados
  também pelo Dockerfile.
- API: token bearer opcional (`ECHO_API_TOKEN`), limite de scans simultâneos (`ECHO_MAX_CONCURRENT`, `429`),
  `GET /api/health`, `GET /api/scans/{id}/report`, parâmetros `profile`, `report_lang`, `format`, `title`,
  `client`, `author` no `POST /api/scans`, progresso por módulo e testes (`go test ./api`).
- CI no GitHub Actions: ShellCheck, gofmt/vet/test/build, ruff, geração de relatório de teste, build e smoke test
  da imagem Docker.
- Banner (`assets/banner.png`) e social preview (`assets/social-preview.png`), README em inglês e pt-BR.

### Alterado
- Imagem base `ubuntu:22.04` → `ubuntu:24.04`; API compilada em estágio separado (`golang:1.26`).
- Ferramentas instaladas a partir dos binários oficiais nas versões de `scripts/versions.env`
  (subfinder 2.17.0, dnsx 1.3.1, naabu 2.7.0, httpx 1.12.0, tlsx 1.5.0, katana 1.8.0, nuclei 3.11.1, gau 2.2.4,
  findomain 11.0.0, nikto 2.6.1) em vez de `go install ...@latest`.
- **Nuclei** roda uma única vez (JSONL; o `.txt` é derivado dele) com pastas de templates válidas no layout atual
  (`http/misconfiguration`, `http/exposures`, `http/exposed-panels`, `http/takeovers`, `ssl`, `dns`, severidade
  low+; tecnologias vêm do httpx), um alvo por host:porta, sem interactsh no perfil standard e com as tags `dos`, `fuzz`, `intrusive`, `bruteforce`,
  `default-login` etc. excluídas. O perfil deep usa o profile `recommended`.
- **naabu** usa connect scan quando não é root (o container roda como usuário sem privilégio), `-exclude-cdn` e
  taxa limitada; padrão top 100 (top 1000 no deep).
- **httpx** grava JSON com status, título, servidor, tecnologias, IP e CDN; varre portas não padrão encontradas.
- **gau** consulta o domínio com `--subs` uma vez (antes rodava por host vivo) e não descarta mais `.js`.
- **Nikto** só no perfil deep, com `-Tuning x6` (sem testes de DoS), `-maxtime` e pausa entre requisições.
- IDs de scan agora incluem a hora (`recon-<domínio>-AAAA-MM-DD-HHMMSS`), permitindo vários scans no mesmo dia.
  A API continua aceitando o formato antigo `recon-<domínio>-AAAA-MM-DD`.
- Erros da API agora são JSON (`{"error": "..."}`).
- Diretório de saída configurável (`-o`, `ECHO_OUTPUT_DIR`); antes era fixo em `/app/output`.

### Removido
- **assetfinder** (sem manutenção; no teste só trouxe o domínio raiz além do que o subfinder já encontra).
- **amass** (a v4 passiva retornou 0 resultados; a v5 exige o engine/servidor próprio e não se encaixa no pipeline).
- **waybackurls** (coberto pelo provider `wayback` do gau) e **getJS** (era usado de forma errada e foi substituído
  por katana + extração própria de endpoints).
- **anew** e **nmap** (não eram necessários / não eram usados).

### Corrigido
- **Build do Docker quebrado**: Go 1.25.7 + `@latest` falhava porque as ferramentas atuais exigem Go ≥ 1.26
  (e o getJS, sem `go.mod`, não consegue trocar de toolchain).
- **Nuclei não rodava nenhum template**: as pastas `technologies,cves,...` não existem mais na raiz do
  nuclei-templates (`no templates provided for scan`) e o erro era escondido por `2>/dev/null`. Também rodava duas
  vezes (texto e JSON), dobrando o tráfego.
- Análise de JS nunca encontrava arquivos vindos do gau (`--blacklist ...,js,...` removia todos os `.js`) e o
  getJS recebia URLs de JS como se fossem páginas.
- Com `set -e`, uma falha do dnsx/naabu/httpx (ou arquivo de saída inexistente) abortava o scan inteiro.
- O scan terminava com erro quando não havia subdomínios/hosts vivos; agora o módulo fica `empty` e o relatório
  é gerado mesmo assim.
- `MAX_SCAN_MINUTES` era lido mas nunca aplicado; agora é um orçamento de tempo real.
- O `-h/--help` e `--install` citados no README não existiam; argumentos só eram aceitos como exatamente `-d X`.
- API: validação fraca de domínio (aceitava valores como `-h`, que viravam argumento do `recon.sh`), sem
  autenticação, sem limite de concorrência, data obtida via `exec date`.
- `useradd -u 1000` falharia no Ubuntu 24.04 (UID já usado pelo usuário `ubuntu`).
- O `httpx` do Python (mesmo nome) era aceito como se fosse o da ProjectDiscovery.

## [2.2] - 2025

- Versão anterior: recon com subfinder/assetfinder/findomain/amass, dnsx, naabu, httpx, waybackurls/gau, getJS,
  nuclei, nikto e ZAP opcional; API REST em Go.

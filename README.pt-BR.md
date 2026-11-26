<p align="center">
  <img src="assets/banner.png" alt="ECHO - Advanced Scan Suite" width="100%">
</p>

<p align="center">
  <b>Português (Brasil)</b> · <a href="README.md">English</a>
</p>

<p align="center">
  <img alt="Bash" src="https://img.shields.io/badge/bash-5%2B-4EAA25?logo=gnubash&logoColor=white">
  <img alt="Go" src="https://img.shields.io/badge/API-Go%20stdlib-00ADD8?logo=go&logoColor=white">
  <img alt="Python" src="https://img.shields.io/badge/relat%C3%B3rios-Python%203%20%2B%20ReportLab-3776AB?logo=python&logoColor=white">
  <img alt="Docker" src="https://img.shields.io/badge/docker-ubuntu%2024.04-2496ED?logo=docker&logoColor=white">
  <img alt="Relatórios" src="https://img.shields.io/badge/relat%C3%B3rios-PDF%20%7C%20JSON%20%7C%20en%20%7C%20pt--BR-00E5A8">
  <a href="https://github.com/stormcrow94/echo-advanced-scan-suite/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/stormcrow94/echo-advanced-scan-suite/actions/workflows/ci.yml/badge.svg"></a>
</p>

O **ECHO** é um pipeline automatizado de reconhecimento externo. Aponte para um domínio que você tem autorização
para testar e ele mapeia a superfície de ataque (subdomínios, DNS, portas, serviços web, TLS, URLs históricas e
rastreadas, endpoints em JavaScript), roda verificações não intrusivas do Nuclei e entrega um **relatório PDF
profissional e um export JSON** em português ou inglês. Funciona como CLI, imagem Docker ou API REST.

> [!WARNING]
> Escaneie apenas ativos que você possui ou tem **autorização por escrito** para testar. Veja [Uso legal e ético](#uso-legal-e-ético).

## Sumário

- [Recursos](#recursos) · [Módulos](#módulos) · [Perfis](#perfis) · [Requisitos](#requisitos)
- [Instalação](#instalação) · [Uso](#uso) · [Relatórios](#relatórios) · [API REST](#api-rest)
- [Estrutura de saída](#estrutura-de-saída) · [Configuração](#configuração) · [Solução de problemas](#solução-de-problemas)
- [Contribuindo](#contribuindo) · [Uso legal e ético](#uso-legal-e-ético) · [Changelog](CHANGELOG.md)

## Recursos

- **Recon passivo + ativo leve** em um comando, com **limite global de taxa** (`--rate`, padrão 50 req/s) e
  **orçamento de tempo** total (`--max-minutes`).
- **Três perfis** (`passive`, `standard`, `deep`) e `--modules` / `--skip` para controle fino.
- **Seguro por padrão**: o Nuclei roda pastas de templates não intrusivos, com tags de DoS, fuzzing, força bruta e
  credenciais padrão excluídas; não há módulos de exploração.
- **Resiliente**: ferramenta ausente só pula o módulo dela; cada módulo grava `ok / empty / skipped / failed` no
  `status.json`; erros fatais das ferramentas aparecem em vez de gerar arquivos vazios em silêncio.
- **Proteção contra falsos positivos**: hosts que respondem em quase todas as portas (firewall/WAF/tarpit) são
  detectados e reduzidos, e redes atrás de proxy transparente *fake-IP* (198.18.0.0/15) são detectadas: os hosts
  são re-resolvidos via DNS-over-HTTPS e a varredura de portas é pulada.
- **Relatórios**: PDF (capa, sumário executivo, gráfico de severidade, tabela de módulos, achados com detalhes,
  superfície de ataque, metodologia) e JSON com [schema estável documentado](docs/REPORT_SCHEMA.md); `en`, `pt-BR`
  ou ambos; título, cliente, autor e logo personalizáveis.
- **Versões fixadas** em um único arquivo ([`scripts/versions.env`](scripts/versions.env)), usado pelo instalador
  nativo e pelo Dockerfile; binários oficiais pré-compilados (sem quebras de `go install @latest`).
- **API REST** (Go, só stdlib) com token bearer opcional, limite de concorrência e download do relatório.

## Módulos

| Módulo | Ferramenta(s) | O que faz | Toca o alvo? |
|---|---|---|---|
| `subdomains` | [subfinder](https://github.com/projectdiscovery/subfinder), [findomain](https://github.com/Findomain/Findomain), crt.sh | Enumeração passiva de subdomínios (Certificate Transparency + fontes públicas) | Não |
| `dns` | [dnsx](https://github.com/projectdiscovery/dnsx) | Resolve A/AAAA/CNAME e mantém só hosts resolvíveis | Só DNS |
| `ports` | [naabu](https://github.com/projectdiscovery/naabu) | Top 100 (standard) / 1000 (deep) portas, connect scan sem root, ciente de CDN | Sim (com limite) |
| `web` | [httpx](https://github.com/projectdiscovery/httpx) | Serviços web ativos, status, título, servidor, tecnologias, CDN | Sim |
| `tls` | [tlsx](https://github.com/projectdiscovery/tlsx) | Certificados: expirado, autoassinado, nome divergente, não confiável, TLS legado | Sim |
| `urls` | [gau](https://github.com/lc/gau) | URLs históricas (Wayback, Common Crawl, OTX, URLScan) | Não |
| `crawl` | [katana](https://github.com/projectdiscovery/katana) | Crawling dos sites (profundidade 3, robots/sitemap, parsing de JS, tempo limitado) | Sim |
| `js` | httpx + curl | Encontra arquivos JavaScript ativos e extrai endpoints/URLs | Sim |
| `nuclei` | [nuclei](https://github.com/projectdiscovery/nuclei) | Templates de misconfiguration, exposições, painéis, takeover, SSL e DNS (low+); o deep adiciona o profile `recommended` e info | Sim |
| `nikto` | [nikto](https://github.com/sullo/nikto) | Verificações do servidor web (só deep, sem testes de DoS, tempo limitado) | Sim |
| `zap` | [ZAP baseline](https://www.zaproxy.org/docs/docker/baseline-scan/) | Scan passivo baseline (deep + `--zap`, requer `zap-baseline.py`) | Sim |

## Perfis

| Perfil | Módulos | Quando usar |
|---|---|---|
| `passive` | subdomains, dns, urls | Só OSINT; nenhum tráfego HTTP ao alvo |
| `standard` *(padrão)* | + ports (top 100), web, tls, crawl, js, nuclei (não intrusivo) | Revisão periódica de exposição externa |
| `deep` | + ports (top 1000), perfil `recommended` do nuclei (CVEs), nikto, zap\* | Avaliações autorizadas com janela de manutenção |

## Requisitos

- **Docker** (recomendado), ou Linux (família Debian/Ubuntu ou RHEL, amd64/arm64) com `bash` ≥ 4, `curl`, `jq`,
  `python3` + `reportlab` (PDF) e as ferramentas de [`scripts/versions.env`](scripts/versions.env).
- Acesso à internet (fontes públicas, download das ferramentas, templates do Nuclei).
- Opcional: chaves de API das fontes do subfinder em `~/.config/subfinder/provider-config.yaml` (mais subdomínios).

## Instalação

### Docker (recomendado)

```bash
git clone https://github.com/stormcrow94/echo-advanced-scan-suite.git
cd echo-advanced-scan-suite
docker build -t echo-scanner .
```

### Nativa (Linux)

```bash
sudo ./scripts/install.sh        # pacotes do sistema + binários fixados em /usr/local/bin
./recon.sh --check-deps          # confere cada ferramenta e os templates do Nuclei
```

Sem root: `PREFIX=$HOME/.local SKIP_SYSTEM_PACKAGES=1 ./scripts/install.sh` (instale `jq`, `libpcap` e
`python3-reportlab` por conta própria). `./recon.sh --install` é um atalho para o instalador.

## Uso

```bash
# Docker: perfil standard, relatório em pt-BR (PDF + JSON)
docker run --rm -v "$PWD/output:/app/output" echo-scanner -d example.com

# Só passivo, relatório JSON em inglês
docker run --rm -v "$PWD/output:/app/output" echo-scanner -d example.com -p passive --format json --report-lang en

# Relatório personalizado nos dois idiomas, taxa baixa, orçamento de 30 minutos
docker run --rm -e TZ=America/Sao_Paulo -v "$PWD/output:/app/output" -v "$PWD/logo.png:/app/logo.png:ro" \
  echo-scanner -d example.com --rate 20 --max-minutes 30 --report-lang both \
  --client "Example Corp" --author "Blue Team" --report-title "Revisão de Exposição Externa" --logo /app/logo.png

# Nativo: só alguns módulos, conferindo o plano antes
./recon.sh -d example.com -m subdomains,dns,web,tls --dry-run
./recon.sh -d example.com -m subdomains,dns,web,tls
```

<details>
<summary><b>Todas as opções</b> (<code>./recon.sh --help</code>)</summary>

| Opção | Padrão | Descrição |
|---|---|---|
| `-d, --domain` | — | Domínio alvo (obrigatório) |
| `-o, --output DIR` | `$ECHO_OUTPUT_DIR`, `/app/output` (Docker) ou `./output` | Diretório raiz de saída |
| `-p, --profile` | `standard` | `passive`, `standard`, `deep` |
| `-m, --modules LISTA` | do perfil | Módulos separados por vírgula (substitui o perfil) |
| `--skip LISTA` | — | Módulos a pular |
| `--rate N` | `50` | Requisições/s ao alvo (dnsx, naabu, httpx, katana, nuclei) |
| `--top-ports N` | 100 / 1000 (deep) | `100` ou `1000` |
| `--max-minutes N` | `60` | Orçamento de tempo; ao estourar, os módulos restantes são pulados |
| `--zap` | desligado | Habilita ZAP baseline (perfil deep) |
| `--dry-run` | — | Mostra o plano e as dependências, sem enviar tráfego |
| `--check-deps` | — | Verifica as ferramentas e sai |
| `--install` | — | Executa `scripts/install.sh` |
| `--no-banner` | — | Oculta o banner ASCII |
| `--report-lang` | `pt-BR` | `en`, `pt-BR`, `both` |
| `--format` | `both` | `pdf`, `json`, `both`, `none` |
| `--report-dir DIR` | `<scan>/report` | Onde gravar os relatórios |
| `--report-title`, `--client`, `--author` | — | Personalização do relatório |
| `--logo ARQUIVO` | — | PNG/JPG exibido na capa |
| `-V, --version`, `-h, --help` | — | Versão / ajuda |

</details>

## Relatórios

Ao fim de cada execução o ECHO chama [`report/echo_report.py`](report/echo_report.py), que lê o diretório do scan e
grava `report-<idioma>.pdf` e/ou `report-<idioma>.json`. Dá para gerar de novo depois, em outro idioma ou com outra
identidade visual, sem escanear novamente:

```bash
python3 report/echo_report.py --scan-dir output/recon-example.com-2026-11-25-120000 \
  --lang pt-BR --format pdf --client "Example Corp" --author "Blue Team" --logo logo.png
```

| Seção do PDF | Conteúdo |
|---|---|
| Capa | Banner, título, alvo, cliente, autor, perfil, início/término/duração (com fuso UTC), risco geral |
| 1. Sumário executivo | Indicadores, achados por severidade (tabela + gráfico), metadados do scan |
| 2. Módulos executados | Status, duração e resultado de cada módulo |
| 3. Achados | Tabela por severidade + detalhes (descrição, recomendação, evidência, referências) dos críticos/altos/médios |
| 4. Superfície de ataque | Serviços web, portas abertas, certificados TLS, subdomínios, amostra de endpoints JS |
| 5. Metodologia e aviso legal | O que foi executado e seus limites |

Exemplos gerados com dados **fictícios** de `example.com`: [`samples/report-pt-BR.pdf`](samples/report-pt-BR.pdf),
[`samples/report-en.pdf`](samples/report-en.pdf), [`samples/report-pt-BR.json`](samples/report-pt-BR.json).
O formato JSON está em [`docs/REPORT_SCHEMA.md`](docs/REPORT_SCHEMA.md) (`schema: echo-report`, `schema_version: 1.0`).

## API REST

```bash
docker run --rm -p 127.0.0.1:8080:8080 -e ECHO_API_TOKEN="$(openssl rand -hex 24)" \
  -v "$PWD/output:/app/output" echo-scanner serve
```

| Método e caminho | Descrição |
|---|---|
| `GET /api/health` | Saúde + número de scans em execução (sem autenticação) |
| `POST /api/scans` | Inicia um scan. Corpo: `{"domain":"example.com","profile":"standard","report_lang":"both","format":"both","client":"…","author":"…","title":"…"}` (só `domain` é obrigatório). Retorna `202` com `{"id":"recon-example.com-2026-11-25-120000","status":"running"}` |
| `GET /api/scans` | Lista os IDs de scan |
| `GET /api/scans/{id}` | Em execução: status + progresso dos módulos. Finalizado: resultado JSON completo (subdomains, hosts, urls, js, vulns, nikto, zap, report_files) |
| `GET /api/scans/{id}/report?format=pdf\|json&lang=en\|pt-BR` | Baixa o relatório gerado |

```bash
TOKEN=…; API=http://127.0.0.1:8080
curl -s -X POST "$API/api/scans" -H "Authorization: Bearer $TOKEN" -d '{"domain":"example.com","report_lang":"pt-BR"}'
curl -s "$API/api/scans/recon-example.com-2026-11-25-120000" -H "Authorization: Bearer $TOKEN" | jq .status
curl -s -o relatorio.pdf "$API/api/scans/recon-example.com-2026-11-25-120000/report?format=pdf&lang=pt-BR" -H "Authorization: Bearer $TOKEN"
```

Configuração da API: `ECHO_API_TOKEN` (fortemente recomendado; sem ele a API fica sem autenticação e registra um
aviso), `ECHO_API_ADDR` (padrão `:8080`), `PORT`, `ECHO_MAX_CONCURRENT` (padrão 2; acima disso retorna `429`),
`OUTPUT_DIR`. Erros vêm em JSON: `{"error":"…"}`. Nunca exponha a API na internet sem token e TLS (proxy reverso).

## Estrutura de saída

```
output/recon-example.com-2026-11-25-120000/
├── status.json              # id, domínio, perfil, horários, status, resultado por módulo
├── recon.log                # log completo do console
├── subdomains.txt           # subdomínios únicos no escopo (+ subdomains/<fonte>.txt)
├── hosts/
│   ├── dns.json             # JSON do dnsx (A/AAAA/CNAME)
│   ├── resolved.txt         # hosts resolvíveis
│   ├── ports.txt            # host:porta abertos (após o filtro de "tudo aberto")
│   ├── ports_all_open.txt   # hosts que respondem em ≥80% das portas (firewall/WAF/tarpit)
│   ├── httpx.json           # detalhes da sondagem web
│   └── alive.txt            # URLs web ativas
├── tls/tlsx.json            # dados dos certificados
├── urls.txt                 # URLs históricas (gau)
├── urls/crawl.txt           # URLs rastreadas (katana)
├── js/js_urls.txt           # arquivos JavaScript ativos
├── js/endpoints.txt         # endpoints extraídos do JS
├── vulns/nuclei.json|.txt   # achados do Nuclei (JSONL + texto)
├── vulns/nikto_*.json       # Nikto (deep)
└── report/report-<idioma>.pdf|.json
```

## Configuração

Variáveis de ambiente (as flags da CLI têm prioridade): `ECHO_OUTPUT_DIR`, `ECHO_PROFILE`, `ECHO_RATE`,
`ECHO_TOP_PORTS`, `MAX_SCAN_MINUTES`, `REPORT_LANG`, `REPORT_FORMAT`, `REPORT_TITLE`, `REPORT_CLIENT`,
`REPORT_AUTHOR`, `REPORT_LOGO`, `NO_COLOR`, `NO_BANNER`, além dos ajustes finos:

| Variável | Padrão | Significado |
|---|---|---|
| `URLS_MAX` | `20000` | Máximo de URLs históricas mantidas |
| `JS_MAX` | `150` | Máximo de arquivos JS baixados para extrair endpoints |
| `CRAWL_DURATION` | `5m` | Tempo máximo de crawling do katana |
| `NUCLEI_TIMEOUT_MIN` | `20` | Limite de tempo do Nuclei (minutos) |
| `NUCLEI_SEVERITY` | `low,medium,high,critical` (standard) / `info,…` (deep) | Severidades reportadas |
| `NUCLEI_EXCLUDE_TAGS` | `dos,fuzz,…,default-login,…` | Tags que nunca rodam |
| `PORTS_ALLOPEN_PCT` | `80` | % das portas abertas que marca um host como "responde tudo" |
| `ECHO_FORCE_PORTS` | `false` | Varre portas mesmo com proxy fake-IP detectado |
| `DOH_URL` | `https://cloudflare-dns.com/dns-query` | Endpoint DNS-over-HTTPS usado para re-resolver hosts em redes fake-IP |
| `NIKTO_MAX_HOSTS` / `ZAP_MAX_HOSTS` | `5` / `3` | Hosts analisados pelo Nikto / ZAP |
| `TZ` (Docker) | `UTC` | Fuso dos horários e relatórios, ex.: `America/Sao_Paulo` |

## Solução de problemas

| Sintoma | Causa / solução |
|---|---|
| Módulo `web` pulado: *"ausente ou é o httpx do Python"* | O CLI `httpx` do Python sobrepõe o da ProjectDiscovery. Instale o httpx da PD (`scripts/install.sh`) e coloque-o antes no `PATH` |
| Todos os hosts com todas as portas abertas | Um firewall/WAF/tarpit responde a todo SYN. O ECHO reduz esses hosts a 80/443 e os lista em `hosts/ports_all_open.txt` |
| *"proxy fake-IP (198.18.0.0/15)"* e `ports` pulado | Sua rede resolve tudo para um proxy transparente (comum em sandboxes e clientes VPN). O ECHO re-resolve os hosts via DoH, mas portas não são confiáveis ali: rode de uma rede normal ou use `ECHO_FORCE_PORTS=true` |
| `subdomains` mostra `crt.sh:0` | O crt.sh vive sobrecarregado (HTTP 502). O ECHO tenta 4 vezes; as outras fontes continuam |
| Poucos subdomínios | Adicione chaves de API em `~/.config/subfinder/provider-config.yaml` |
| Sem PDF, só JSON | Falta o `reportlab`: `apt install python3-reportlab` (ou `pip install --user reportlab`) |
| `Permission denied` em `output/` | O container roda com UID 1000: `sudo chown -R 1000:1000 output/` |
| Nuclei `no templates provided` | Templates não baixados: `nuclei -ut` (feito automaticamente na 1ª execução e no build da imagem) |

## Contribuindo

1. Crie um branch, mantenha as mudanças focadas e atualize o `CHANGELOG.md`.
2. Rode as mesmas verificações da CI: `shellcheck -x recon.sh entrypoint.sh scripts/install.sh`,
   `go vet ./api && go test ./api`, `ruff check report tests` e
   `python3 tests/make_fixture.py /tmp/fx && python3 report/echo_report.py --scan-dir /tmp/fx/recon-example.com-2026-11-25-120000 --lang both`.
3. Para atualizar uma ferramenta, edite `scripts/versions.env`, reconstrua a imagem e rode um scan contra um domínio seu.
4. Use `example.com` (e IPs da RFC 5737) em docs, testes e exemplos — nunca dados reais de clientes.

## Uso legal e ético

O ECHO é destinado a **avaliações de segurança autorizadas** de ativos que você possui ou tem permissão explícita e
por escrito para testar. Mesmo uma varredura "leve" pode ser ilegal sem autorização, pode acionar IDS/IPS e deve
respeitar os termos das fontes de dados de terceiros consultadas. Você é o único responsável pelo uso desta
ferramenta; os autores não se responsabilizam por uso indevido ou danos. Os resultados são automatizados, podem
conter falsos positivos e não substituem um pentest manual.

## Licença

Ainda não há um arquivo de licença. Até que um seja adicionado, todos os direitos são reservados ao autor.

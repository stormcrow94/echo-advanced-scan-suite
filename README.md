# ECHO - Advanced Scan Suite

[English](#english) | [Português](#português)

---

## English

An automated reconnaissance scanner built with Docker for comprehensive security assessment and information gathering.

## Features

- **Subdomain Enumeration**: Discovers subdomains using multiple tools (subfinder, assetfinder, findomain, amass)
- **DNS Resolution**: Validates and resolves discovered subdomains with dnsx
- **Port Scanning**: Scans top 1000 ports using naabu
- **Active Host Detection**: Identifies live web servers with httpx
- **URL Collection**: Gathers historical URLs from Wayback Machine and other sources
- **JavaScript Analysis**: Extracts endpoints from JavaScript files using getJS
- **Vulnerability Scanning**: Comprehensive vulnerability detection with Nuclei (CVEs, misconfigurations, exposure, takeovers, secrets)
- **Nikto**: Web server misconfigurations, dangerous files, and security headers (first N hosts, time-bounded)
- **Optional ZAP baseline**: Light crawl and passive scan when enabled via env (time-boxed per host)

## Prerequisites

- Docker installed on your system
- Sufficient disk space for scan results
- Network connectivity for external reconnaissance tools

## Installation

1. Clone the repository:
```bash
git clone https://github.com/stormcrow94/echo-advanced-scan-suite.git
cd echo-advanced-scan-suite
```

2. Build the Docker image:
```bash
docker build -t echo-scanner .
```

## Usage

### CLI scan (default)

Run a scan against a target domain:

```bash
docker run --rm -v $(pwd)/output:/app/output echo-scanner -d example.com
```

### REST API mode

Run the container in API mode so external services can trigger scans and consume JSON reports:

```bash
docker run --rm -p 8080:8080 -v $(pwd)/output:/app/output echo-scanner serve
```

The API listens on port 8080. Configure with env: `PORT` (default 8080), `OUTPUT_DIR` (default `/app/output`).

**Endpoints:**

- **POST /api/scans** — Start a new scan. Body: `{"domain": "example.com"}`. Returns `202 Accepted` with `{"id": "recon-example.com-YYYY-MM-DD", "status": "running"}`.
- **GET /api/scans** — List scan IDs: `{"scans": ["recon-example.com-2025-02-25", ...]}`.
- **GET /api/scans/:id** — Get scan status or full report. While running: `{"id": "...", "status": "running", "started_at": "..."}`. When completed: full JSON report (subdomains, hosts, urls, js, vulns, nikto, zap).

**Example (start scan, then poll for report):**

```bash
# Start scan
curl -s -X POST http://localhost:8080/api/scans -H "Content-Type: application/json" -d '{"domain":"example.com"}'
# → {"id":"recon-example.com-2025-02-25","status":"running"}

# Poll until completed, then response is the report
curl -s http://localhost:8080/api/scans/recon-example.com-2025-02-25
```

Reports are a single JSON object with `id`, `domain`, `status`, `started_at`, `finished_at`, `subdomains`, `hosts`, `urls`, `js`, `vulns` (Nuclei), and optionally `nikto` and `zap` when those tools ran.

### Command Options

- `-d, --domain`: Target domain for reconnaissance (required for CLI scan)
- `serve` or `--serve`: Run the REST API server instead of a one-off scan
- `--install`: Install all tools and dependencies (for local installation)
- `-h, --help`: Show help message

### Example

```bash
docker run --rm -v $(pwd)/output:/app/output echo-scanner -d example.com
```

Results will be saved in `./output/recon-example.com-YYYY-MM-DD/`

## Output Structure

```
output/
└── recon-example.com-YYYY-MM-DD/
    ├── status.json            # Scan status (started_at, finished_at, status)
    ├── recon.log               # Full execution log
    ├── subdomains.txt          # All discovered subdomains
    ├── urls.txt                # Historical URLs collected
    ├── hosts/
    │   ├── resolved.txt        # DNS-resolved subdomains
    │   ├── ports.txt            # Open ports discovered
    │   └── alive.txt            # Active web servers
    ├── js/
    │   ├── js_urls.txt          # JavaScript URLs
    │   └── endpoints.txt       # Endpoints extracted from JavaScript
    └── vulns/
        ├── nuclei.txt          # Nuclei scan (text)
        ├── nuclei.json         # Nuclei findings (JSONL, for API report)
        ├── nikto_*.json        # Nikto results per host (when run)
        └── zap_*.json          # ZAP baseline results per host (optional)
```

## Tools Included

- **subfinder** - Fast subdomain discovery tool
- **assetfinder** - Find domains and subdomains
- **findomain** - Cross-platform subdomain enumerator
- **amass** - In-depth DNS enumeration and network mapping
- **dnsx** - Fast DNS resolver
- **naabu** - Port scanning tool
- **httpx** - HTTP toolkit for web host detection
- **waybackurls** - Fetch URLs from Wayback Machine
- **gau** - Get All URLs from multiple sources
- **getJS** - JavaScript file analysis
- **nuclei** - Vulnerability scanner (CVEs, misconfigurations, exposure, takeovers, secrets)
- **nikto** - Web server scanner (misconfigs, dangerous files, headers)
- **ZAP baseline** (optional) - Light crawl + passive scan when `ZAP_BASELINE_ENABLED=true` and ZAP is installed

## Scan Stages

The scanner performs the following stages automatically:

1. **Subdomain Enumeration** - Discovers subdomains using multiple tools
2. **DNS Resolution** - Validates which subdomains resolve
3. **Port Scanning** - Scans top 1000 ports on resolved hosts
4. **Web Server Detection** - Identifies active HTTP/HTTPS services
5. **URL Collection** - Gathers historical URLs from Wayback Machine and other sources
6. **JavaScript Analysis** - Extracts endpoints from JavaScript files
7. **Vulnerability Scanning** - Runs Nuclei (with exposure, takeover, secret templates; rate-limited)
8. **Nikto** - Web server checks on first N alive hosts (timeout per host)
9. **ZAP baseline** (optional) - Light crawl + passive scan on first M hosts when enabled

## Local Installation (Without Docker)

If you prefer to install tools locally:

```bash
chmod +x recon.sh
./recon.sh --install
```

Then run scans directly:
```bash
./recon.sh -d example.com
```

## Security Notes

- This tool is intended for authorized security assessments only
- Always obtain proper authorization before scanning any domain
- Respect rate limits and terms of service of external APIs
- Some tools may trigger IDS/IPS systems

## Performance Tips & Time Budget

- **Target scan time**: About 20–30 minutes per run (configurable). Scans use per-stage timeouts to stay within this range.
- **Env vars** (optional):
  - `MAX_SCAN_MINUTES` - Soft cap for total scan time (default: 30).
  - `NIKTO_MAX_HOSTS` - Number of alive hosts to run Nikto on (default: 10).
  - `ZAP_BASELINE_ENABLED` - Set to `true` to run ZAP baseline on first M hosts (default: false; requires ZAP in the image or sidecar).
  - `ZAP_MAX_HOSTS` - Number of hosts for ZAP baseline when enabled (default: 5).
- Port scanning and Nuclei are the most time-intensive phases; Nuclei is run with concurrency and rate limits.
- Use the Docker volume mount to preserve results between runs.

## Troubleshooting

**Permission Issues:**
```bash
sudo chown -R $USER:$USER output/
```

**Docker Build Errors:**
- Ensure you have a stable internet connection
- Some Go package installations may take time

**Scan Timeouts:**
- Normal for large targets with many subdomains
- Results up to the timeout point are still saved

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

## License

This project is provided as-is for educational and authorized security testing purposes.

## Disclaimer

This tool is for educational and ethical testing purposes only. Users are responsible for complying with applicable laws and regulations. The authors are not responsible for any misuse or damage caused by this tool.

---

## Português

Um scanner de reconhecimento automatizado construído com Docker para avaliação de segurança abrangente e coleta de informações.

## Funcionalidades

- **Enumeração de Subdomínios**: Descobre subdomínios usando múltiplas ferramentas (subfinder, assetfinder, findomain, amass)
- **Resolução DNS**: Valida e resolve subdomínios descobertos com dnsx
- **Varredura de Portas**: Escaneia as 1000 portas principais usando naabu
- **Detecção de Hosts Ativos**: Identifica servidores web ativos com httpx
- **Coleta de URLs**: Reúne URLs históricas do Wayback Machine e outras fontes
- **Análise de JavaScript**: Extrai endpoints de arquivos JavaScript usando getJS
- **Varredura de Vulnerabilidades**: Detecção com Nuclei (CVEs, misconfigurações, exposição, takeovers, secrets)
- **Nikto**: Misconfigurações de servidor web, arquivos perigosos e headers de segurança (primeiros N hosts, com timeout)
- **ZAP baseline (opcional)**: Crawl leve e varredura passiva quando ativado via env (limitado por tempo por host)

## Pré-requisitos

- Docker instalado no seu sistema
- Espaço em disco suficiente para os resultados das varreduras
- Conectividade de rede para ferramentas de reconhecimento externas

## Instalação

1. Clone o repositório:
```bash
git clone https://github.com/stormcrow94/echo-advanced-scan-suite.git
cd echo-advanced-scan-suite
```

2. Construa a imagem Docker:
```bash
docker build -t echo-scanner .
```

## Uso

### Varredura via CLI (padrão)

Execute uma varredura contra um domínio alvo:

```bash
docker run --rm -v $(pwd)/output:/app/output echo-scanner -d exemplo.com
```

### Modo API REST

Execute o container no modo API para que outros serviços possam disparar varreduras e consumir relatórios em JSON:

```bash
docker run --rm -p 8080:8080 -v $(pwd)/output:/app/output echo-scanner serve
```

A API escuta na porta 8080. Configure com env: `PORT` (padrão 8080), `OUTPUT_DIR` (padrão `/app/output`).

**Endpoints:** POST /api/scans (iniciar scan), GET /api/scans (listar), GET /api/scans/:id (status ou relatório JSON completo). Relatórios incluem subdomains, hosts, urls, js, vulns (Nuclei), nikto e zap quando aplicável.

### Opções de Comando

- `-d, --domain`: Domínio alvo para reconhecimento (obrigatório no modo CLI)
- `serve` ou `--serve`: Executar o servidor da API REST em vez de uma varredura única
- `--install`: Instala todas as ferramentas e dependências (para instalação local)
- `-h, --help`: Mostra mensagem de ajuda

### Exemplo

```bash
docker run --rm -v $(pwd)/output:/app/output echo-scanner -d exemplo.com
```

Os resultados serão salvos em `./output/recon-exemplo.com-YYYY-MM-DD/`

## Estrutura de Saída

```
output/
└── recon-exemplo.com-YYYY-MM-DD/
    ├── status.json            # Status do scan (started_at, finished_at, status)
    ├── recon.log               # Log completo de execução
    ├── subdomains.txt          # Todos os subdomínios descobertos
    ├── urls.txt                # URLs históricas coletadas
    ├── hosts/
    │   ├── resolved.txt        # Subdomínios resolvidos via DNS
    │   ├── ports.txt           # Portas abertas descobertas
    │   └── alive.txt           # Servidores web ativos
    ├── js/
    │   ├── js_urls.txt         # URLs de JavaScript
    │   └── endpoints.txt       # Endpoints extraídos do JavaScript
    └── vulns/
        ├── nuclei.txt         # Nuclei (texto)
        ├── nuclei.json        # Nuclei (JSONL, para relatório da API)
        ├── nikto_*.json       # Resultados Nikto por host
        └── zap_*.json         # Resultados ZAP baseline por host (opcional)
```

## Ferramentas Incluídas

- **subfinder** - Ferramenta rápida de descoberta de subdomínios
- **assetfinder** - Encontra domínios e subdomínios
- **findomain** - Enumerador de subdomínios multiplataforma
- **amass** - Enumeração DNS aprofundada e mapeamento de rede
- **dnsx** - Resolvedor DNS rápido
- **naabu** - Ferramenta de varredura de portas
- **httpx** - Kit de ferramentas HTTP para detecção de hosts web
- **waybackurls** - Busca URLs do Wayback Machine
- **gau** - Obtém todas as URLs de múltiplas fontes
- **getJS** - Análise de arquivos JavaScript
- **nuclei** - Scanner de vulnerabilidades (CVEs, misconfigs, exposure, takeovers, secrets)
- **nikto** - Scanner de servidor web (misconfigs, arquivos perigosos, headers)
- **ZAP baseline** (opcional) - Crawl leve + varredura passiva quando `ZAP_BASELINE_ENABLED=true` e ZAP instalado

## Etapas da Varredura

O scanner executa as seguintes etapas automaticamente:

1. **Enumeração de Subdomínios** - Descobre subdomínios usando múltiplas ferramentas
2. **Resolução DNS** - Valida quais subdomínios são resolvidos
3. **Varredura de Portas** - Escaneia as 1000 portas principais nos hosts resolvidos
4. **Detecção de Servidores Web** - Identifica serviços HTTP/HTTPS ativos
5. **Coleta de URLs** - Reúne URLs históricas do Wayback Machine e outras fontes
6. **Análise de JavaScript** - Extrai endpoints de arquivos JavaScript
7. **Varredura de Vulnerabilidades** - Executa Nuclei (exposure, takeover, secret; com rate limit)
8. **Nikto** - Verificações de servidor web nos primeiros N hosts (timeout por host)
9. **ZAP baseline** (opcional) - Crawl leve + varredura passiva nos primeiros M hosts quando ativado

## Instalação Local (Sem Docker)

Se você preferir instalar as ferramentas localmente:

```bash
chmod +x recon.sh
./recon.sh --install
```

Depois execute as varreduras diretamente:
```bash
./recon.sh -d exemplo.com
```

## Notas de Segurança

- Esta ferramenta é destinada apenas para avaliações de segurança autorizadas
- Sempre obtenha autorização adequada antes de escanear qualquer domínio
- Respeite limites de taxa e termos de serviço de APIs externas
- Algumas ferramentas podem acionar sistemas IDS/IPS

## Dicas de Performance e Tempo de Varredura

- **Tempo alvo**: Cerca de 20–30 minutos por execução (configurável). As varreduras usam timeouts por etapa para respeitar esse intervalo.
- **Variáveis de ambiente** (opcionais): `MAX_SCAN_MINUTES`, `NIKTO_MAX_HOSTS`, `ZAP_BASELINE_ENABLED`, `ZAP_MAX_HOSTS` (veja a seção em inglês para detalhes).
- Varredura de portas e Nuclei são as fases mais demoradas; Nuclei é executado com concorrência e rate limits.
- Use o volume do Docker para preservar resultados entre execuções.

## Solução de Problemas

**Problemas de Permissão:**
```bash
sudo chown -R $USER:$USER output/
```

**Erros de Build do Docker:**
- Certifique-se de ter uma conexão estável com a internet
- Algumas instalações de pacotes Go podem levar tempo

**Timeouts de Varredura:**
- Normal para alvos grandes com muitos subdomínios
- Resultados até o ponto de timeout ainda são salvos

## Contribuindo

Contribuições são bem-vindas! Sinta-se à vontade para enviar issues ou pull requests.

## Licença

Este projeto é fornecido como está para fins educacionais e testes de segurança autorizados.

## Aviso Legal

Esta ferramenta é apenas para fins educacionais e testes éticos. Os usuários são responsáveis por cumprir as leis e regulamentos aplicáveis. Os autores não são responsáveis por qualquer uso indevido ou danos causados por esta ferramenta.
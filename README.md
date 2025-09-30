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
- **Vulnerability Scanning**: Comprehensive vulnerability detection with Nuclei

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

Run a scan against a target domain:

```bash
docker run --rm -v $(pwd)/output:/app/output echo-scanner -d example.com
```

### Command Options

- `-d, --domain`: Target domain for reconnaissance (required)
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
    ├── recon.log              # Full execution log
    ├── subdomains.txt         # All discovered subdomains
    ├── urls.txt               # Historical URLs collected
    ├── hosts/
    │   ├── resolved.txt       # DNS-resolved subdomains
    │   ├── ports.txt          # Open ports discovered
    │   └── alive.txt          # Active web servers
    ├── js/
    │   └── endpoints.txt      # Endpoints extracted from JavaScript
    └── vulns/
        └── nuclei.txt         # Nuclei vulnerability scan results
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
- **nuclei** - Vulnerability scanner with templates

## Scan Stages

The scanner performs the following stages automatically:

1. **Subdomain Enumeration** - Discovers subdomains using multiple tools
2. **DNS Resolution** - Validates which subdomains resolve
3. **Port Scanning** - Scans top 1000 ports on resolved hosts
4. **Web Server Detection** - Identifies active HTTP/HTTPS services
5. **URL Collection** - Gathers historical URLs from Wayback Machine and other sources
6. **JavaScript Analysis** - Extracts endpoints from JavaScript files
7. **Vulnerability Scanning** - Runs Nuclei to detect security issues

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

## Performance Tips

- Scans can take 10-30 minutes depending on target size
- Port scanning and Nuclei vulnerability scanning are the most time-intensive phases
- Use the Docker volume mount to preserve results between runs
- Adjust timeout values in the script for faster scans if needed

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
- **Varredura de Vulnerabilidades**: Detecção abrangente de vulnerabilidades com Nuclei

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

Execute uma varredura contra um domínio alvo:

```bash
docker run --rm -v $(pwd)/output:/app/output echo-scanner -d exemplo.com
```

### Opções de Comando

- `-d, --domain`: Domínio alvo para reconhecimento (obrigatório)
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
    ├── recon.log              # Log completo de execução
    ├── subdomains.txt         # Todos os subdomínios descobertos
    ├── urls.txt               # URLs históricas coletadas
    ├── hosts/
    │   ├── resolved.txt       # Subdomínios resolvidos via DNS
    │   ├── ports.txt          # Portas abertas descobertas
    │   └── alive.txt          # Servidores web ativos
    ├── js/
    │   └── endpoints.txt      # Endpoints extraídos do JavaScript
    └── vulns/
        └── nuclei.txt         # Resultados da varredura Nuclei
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
- **nuclei** - Scanner de vulnerabilidades com templates

## Etapas da Varredura

O scanner executa as seguintes etapas automaticamente:

1. **Enumeração de Subdomínios** - Descobre subdomínios usando múltiplas ferramentas
2. **Resolução DNS** - Valida quais subdomínios são resolvidos
3. **Varredura de Portas** - Escaneia as 1000 portas principais nos hosts resolvidos
4. **Detecção de Servidores Web** - Identifica serviços HTTP/HTTPS ativos
5. **Coleta de URLs** - Reúne URLs históricas do Wayback Machine e outras fontes
6. **Análise de JavaScript** - Extrai endpoints de arquivos JavaScript
7. **Varredura de Vulnerabilidades** - Executa Nuclei para detectar problemas de segurança

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

## Dicas de Performance

- As varreduras podem levar de 10 a 30 minutos dependendo do tamanho do alvo
- Varredura de portas e varredura de vulnerabilidades com Nuclei são as fases mais demoradas
- Use o volume mount do Docker para preservar resultados entre execuções
- Ajuste valores de timeout no script para varreduras mais rápidas se necessário

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
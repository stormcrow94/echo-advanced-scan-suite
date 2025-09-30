# ECHO - Advanced Scan Suite

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
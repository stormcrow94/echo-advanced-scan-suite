<p align="center">
  <img src="assets/banner.png" alt="ECHO - Advanced Scan Suite" width="100%">
</p>

<p align="center">
  <a href="README.pt-BR.md">Português (Brasil)</a> · <b>English</b>
</p>

<p align="center">
  <img alt="Bash" src="https://img.shields.io/badge/bash-5%2B-4EAA25?logo=gnubash&logoColor=white">
  <img alt="Go" src="https://img.shields.io/badge/API-Go%20stdlib-00ADD8?logo=go&logoColor=white">
  <img alt="Python" src="https://img.shields.io/badge/reports-Python%203%20%2B%20ReportLab-3776AB?logo=python&logoColor=white">
  <img alt="Docker" src="https://img.shields.io/badge/docker-ubuntu%2024.04-2496ED?logo=docker&logoColor=white">
  <img alt="Reports" src="https://img.shields.io/badge/reports-PDF%20%7C%20JSON%20%7C%20en%20%7C%20pt--BR-00E5A8">
  <a href="https://github.com/stormcrow94/echo-advanced-scan-suite/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/stormcrow94/echo-advanced-scan-suite/actions/workflows/ci.yml/badge.svg"></a>
</p>

**ECHO** is an automated external reconnaissance pipeline. Point it at a domain you are authorized to test and it
maps the attack surface (subdomains, DNS, ports, web services, TLS, historical and crawled URLs, JavaScript
endpoints), runs non-intrusive Nuclei checks and delivers a **professional PDF report and a machine-readable JSON
export** in English or Brazilian Portuguese. It runs as a CLI, as a Docker image or as a small REST API.

> [!WARNING]
> Only scan assets you own or have **written authorization** to test. See [Legal & ethical use](#legal--ethical-use).

## Contents

- [Features](#features) · [Modules](#modules) · [Profiles](#profiles) · [Requirements](#requirements)
- [Installation](#installation) · [Usage](#usage) · [Reports](#reports) · [REST API](#rest-api)
- [Output structure](#output-structure) · [Configuration](#configuration) · [Troubleshooting](#troubleshooting)
- [Contributing](#contributing) · [Legal & ethical use](#legal--ethical-use) · [Changelog](CHANGELOG.md)

## Features

- **Passive + light active recon** in one command, with a global **rate limit** (`--rate`, default 50 req/s)
  and a total **time budget** (`--max-minutes`).
- **Three profiles** (`passive`, `standard`, `deep`) plus `--modules` / `--skip` for fine control.
- **Safe by default**: Nuclei runs non-intrusive template folders with DoS, fuzzing, brute-force and
  default-credential tags excluded; no exploitation modules.
- **Resilient**: missing tools only skip their module, each module records `ok / empty / skipped / failed`
  in `status.json`, tool fatal errors are surfaced instead of silently producing empty files.
- **False-positive guards**: hosts that answer on almost every port (firewalls/WAF/tarpits) are detected and
  trimmed, and networks behind a *fake-IP* transparent proxy (198.18.0.0/15) are detected: hosts are
  re-resolved over DNS-over-HTTPS and the port scan is skipped.
- **Reports**: PDF (cover, executive summary, severity chart, module table, findings with details, attack
  surface tables, methodology) and JSON with a [documented stable schema](docs/REPORT_SCHEMA.md);
  `en`, `pt-BR` or both; custom title, client, author and logo.
- **Pinned tool versions** in one file ([`scripts/versions.env`](scripts/versions.env)) shared by the native
  installer and the Dockerfile; prebuilt official binaries (no `go install @latest` breakage).
- **REST API** (Go, stdlib only) with optional bearer token, concurrency limit and report download.

## Modules

| Module | Tool(s) | What it does | Touches the target? |
|---|---|---|---|
| `subdomains` | [subfinder](https://github.com/projectdiscovery/subfinder), [findomain](https://github.com/Findomain/Findomain), crt.sh | Passive subdomain enumeration (Certificate Transparency + public sources) | No |
| `dns` | [dnsx](https://github.com/projectdiscovery/dnsx) | Resolves A/AAAA/CNAME, keeps only resolvable hosts | DNS only |
| `ports` | [naabu](https://github.com/projectdiscovery/naabu) | Top 100 (standard) / 1000 (deep) ports, connect scan without root, CDN-aware | Yes (rate-limited) |
| `web` | [httpx](https://github.com/projectdiscovery/httpx) | Live web services, status, title, server, technologies, CDN | Yes |
| `tls` | [tlsx](https://github.com/projectdiscovery/tlsx) | Certificates: expired, self-signed, hostname mismatch, untrusted, legacy TLS | Yes |
| `urls` | [gau](https://github.com/lc/gau) | Historical URLs (Wayback, Common Crawl, OTX, URLScan) | No |
| `crawl` | [katana](https://github.com/projectdiscovery/katana) | Crawls live sites (depth 3, robots/sitemap, JS parsing, time-boxed) | Yes |
| `js` | httpx + curl | Finds live JavaScript files and extracts endpoints/URLs | Yes |
| `nuclei` | [nuclei](https://github.com/projectdiscovery/nuclei) | Misconfiguration, exposure, panels, takeovers, SSL and DNS templates (low+); deep adds the `recommended` profile and info | Yes |
| `nikto` | [nikto](https://github.com/sullo/nikto) | Web server checks (deep only, DoS tuning excluded, time-boxed) | Yes |
| `zap` | [ZAP baseline](https://www.zaproxy.org/docs/docker/baseline-scan/) | Passive baseline scan (deep + `--zap`, needs `zap-baseline.py`) | Yes |

## Profiles

| Profile | Modules | Use it for |
|---|---|---|
| `passive` | subdomains, dns, urls | OSINT only; no HTTP traffic to the target |
| `standard` *(default)* | + ports (top 100), web, tls, crawl, js, nuclei (non-intrusive) | Regular external exposure review |
| `deep` | + ports (top 1000), nuclei `recommended` profile (CVEs), nikto, zap\* | Authorized assessments with a maintenance window |

## Requirements

- **Docker** (recommended), or a Linux host (Debian/Ubuntu or RHEL family, amd64/arm64) with `bash` ≥ 4,
  `curl`, `jq`, `python3` + `reportlab` (PDF) and the tools in [`scripts/versions.env`](scripts/versions.env).
- Outbound internet access (public sources, tool downloads, Nuclei templates).
- Optional API keys for subfinder sources in `~/.config/subfinder/provider-config.yaml` (more subdomains).

## Installation

### Docker (recommended)

```bash
git clone https://github.com/stormcrow94/echo-advanced-scan-suite.git
cd echo-advanced-scan-suite
docker build -t echo-scanner .
```

### Native (Linux)

```bash
sudo ./scripts/install.sh        # system packages + pinned tool binaries in /usr/local/bin
./recon.sh --check-deps          # verifies every tool and the Nuclei templates
```

Without root: `PREFIX=$HOME/.local SKIP_SYSTEM_PACKAGES=1 ./scripts/install.sh` (install `jq`, `libpcap` and
`python3-reportlab` yourself). `./recon.sh --install` is a shortcut for the installer.

## Usage

```bash
# Docker: standard profile, report in pt-BR (PDF + JSON)
docker run --rm -v "$PWD/output:/app/output" echo-scanner -d example.com

# Passive only, JSON report in English
docker run --rm -v "$PWD/output:/app/output" echo-scanner -d example.com -p passive --format json --report-lang en

# Branded report in both languages, gentle rate, 30-minute budget
docker run --rm -e TZ=America/Sao_Paulo -v "$PWD/output:/app/output" -v "$PWD/logo.png:/app/logo.png:ro" \
  echo-scanner -d example.com --rate 20 --max-minutes 30 --report-lang both \
  --client "Example Corp" --author "Blue Team" --report-title "External Exposure Review" --logo /app/logo.png

# Native: only some modules, preview the plan first
./recon.sh -d example.com -m subdomains,dns,web,tls --dry-run
./recon.sh -d example.com -m subdomains,dns,web,tls
```

<details>
<summary><b>All options</b> (<code>./recon.sh --help</code>)</summary>

| Option | Default | Description |
|---|---|---|
| `-d, --domain` | — | Target domain (required) |
| `-o, --output DIR` | `$ECHO_OUTPUT_DIR`, `/app/output` (Docker) or `./output` | Output root |
| `-p, --profile` | `standard` | `passive`, `standard`, `deep` |
| `-m, --modules LIST` | profile | Comma-separated module list (overrides profile) |
| `--skip LIST` | — | Modules to skip |
| `--rate N` | `50` | Requests/s sent to the target (dnsx, naabu, httpx, katana, nuclei) |
| `--top-ports N` | 100 / 1000 (deep) | `100` or `1000` |
| `--max-minutes N` | `60` | Time budget; remaining modules are skipped once exceeded |
| `--zap` | off | Enable ZAP baseline (deep profile) |
| `--dry-run` | — | Print the plan and dependency check, send no traffic |
| `--check-deps` | — | Check installed tools and exit |
| `--install` | — | Run `scripts/install.sh` |
| `--no-banner` | — | Hide the ASCII banner |
| `--report-lang` | `pt-BR` | `en`, `pt-BR`, `both` |
| `--format` | `both` | `pdf`, `json`, `both`, `none` |
| `--report-dir DIR` | `<scan>/report` | Where reports are written |
| `--report-title`, `--client`, `--author` | — | Report customization |
| `--logo FILE` | — | PNG/JPG shown on the cover |
| `-V, --version`, `-h, --help` | — | Version / help |

</details>

## Reports

After every run ECHO calls [`report/echo_report.py`](report/echo_report.py), which reads the scan directory and
writes `report-<lang>.pdf` and/or `report-<lang>.json`. You can also re-generate reports later, e.g. in another
language or with different branding, without scanning again:

```bash
python3 report/echo_report.py --scan-dir output/recon-example.com-2026-11-25-120000 \
  --lang en --format pdf --client "Example Corp" --author "Blue Team" --logo logo.png
```

| PDF section | Content |
|---|---|
| Cover | Banner, title, target, client, author, profile, start/end/duration (with UTC offset), overall risk |
| 1. Executive summary | KPIs, findings by severity (table + chart), scan metadata |
| 2. Modules executed | Status, duration and result of every module |
| 3. Findings | Table sorted by severity + details (description, recommendation, evidence, references) for critical/high/medium |
| 4. Attack surface | Web services, open ports, TLS certificates, subdomains, sample of JS endpoints |
| 5. Methodology & disclaimer | What was run and its limits |

Samples generated from **fake** `example.com` data: [`samples/report-en.pdf`](samples/report-en.pdf),
[`samples/report-pt-BR.pdf`](samples/report-pt-BR.pdf), [`samples/report-en.json`](samples/report-en.json).
The JSON layout is documented in [`docs/REPORT_SCHEMA.md`](docs/REPORT_SCHEMA.md) (`schema: echo-report`, `schema_version: 1.0`).

## REST API

```bash
docker run --rm -p 127.0.0.1:8080:8080 -e ECHO_API_TOKEN="$(openssl rand -hex 24)" \
  -v "$PWD/output:/app/output" echo-scanner serve
```

| Method & path | Description |
|---|---|
| `GET /api/health` | Liveness + number of running scans (no auth) |
| `POST /api/scans` | Start a scan. Body: `{"domain":"example.com","profile":"standard","report_lang":"both","format":"both","client":"…","author":"…","title":"…"}` (only `domain` is required). Returns `202` with `{"id":"recon-example.com-2026-11-25-120000","status":"running"}` |
| `GET /api/scans` | List scan IDs |
| `GET /api/scans/{id}` | While running: status + module progress. When finished: full JSON result (subdomains, hosts, urls, js, vulns, nikto, zap, report_files) |
| `GET /api/scans/{id}/report?format=pdf\|json&lang=en\|pt-BR` | Download the generated report |

```bash
TOKEN=…; API=http://127.0.0.1:8080
curl -s -X POST "$API/api/scans" -H "Authorization: Bearer $TOKEN" -d '{"domain":"example.com","report_lang":"en"}'
curl -s "$API/api/scans/recon-example.com-2026-11-25-120000" -H "Authorization: Bearer $TOKEN" | jq .status
curl -s -o report.pdf "$API/api/scans/recon-example.com-2026-11-25-120000/report?format=pdf&lang=en" -H "Authorization: Bearer $TOKEN"
```

API settings: `ECHO_API_TOKEN` (strongly recommended; without it the API is unauthenticated and logs a warning),
`ECHO_API_ADDR` (default `:8080`), `PORT`, `ECHO_MAX_CONCURRENT` (default 2, returns `429` beyond it),
`OUTPUT_DIR`. Errors are JSON: `{"error":"…"}`. Never expose the API to the internet without a token and TLS
(reverse proxy).

## Output structure

```
output/recon-example.com-2026-11-25-120000/
├── status.json              # id, domain, profile, timestamps, status, per-module results
├── recon.log                # full console log
├── subdomains.txt           # unique in-scope subdomains (+ subdomains/<source>.txt)
├── hosts/
│   ├── dns.json             # dnsx JSON (A/AAAA/CNAME)
│   ├── resolved.txt         # resolvable hosts
│   ├── ports.txt            # host:port open (after all-open filter)
│   ├── ports_all_open.txt   # hosts answering on ≥80% of ports (firewall/WAF/tarpit)
│   ├── httpx.json           # web probe details
│   └── alive.txt            # live web URLs
├── tls/tlsx.json            # certificate data
├── urls.txt                 # historical URLs (gau)
├── urls/crawl.txt           # crawled URLs (katana)
├── js/js_urls.txt           # live JavaScript files
├── js/endpoints.txt         # endpoints extracted from JS
├── vulns/nuclei.json|.txt   # Nuclei findings (JSONL + text)
├── vulns/nikto_*.json       # Nikto (deep)
└── report/report-<lang>.pdf|.json
```

## Configuration

Environment variables (CLI flags take precedence): `ECHO_OUTPUT_DIR`, `ECHO_PROFILE`, `ECHO_RATE`,
`ECHO_TOP_PORTS`, `MAX_SCAN_MINUTES`, `REPORT_LANG`, `REPORT_FORMAT`, `REPORT_TITLE`, `REPORT_CLIENT`,
`REPORT_AUTHOR`, `REPORT_LOGO`, `NO_COLOR`, `NO_BANNER`, plus tuning knobs:

| Variable | Default | Meaning |
|---|---|---|
| `URLS_MAX` | `20000` | Max historical URLs kept |
| `JS_MAX` | `150` | Max JavaScript files downloaded for endpoint extraction |
| `CRAWL_DURATION` | `5m` | Max katana crawl time |
| `NUCLEI_TIMEOUT_MIN` | `20` | Nuclei time limit (minutes) |
| `NUCLEI_SEVERITY` | `low,medium,high,critical` (standard) / `info,…` (deep) | Severities reported |
| `NUCLEI_EXCLUDE_TAGS` | `dos,fuzz,…,default-login,…` | Tags never run |
| `PORTS_ALLOPEN_PCT` | `80` | % of scanned ports open that marks a host as "answers everything" |
| `ECHO_FORCE_PORTS` | `false` | Port-scan even when a fake-IP proxy is detected |
| `DOH_URL` | `https://cloudflare-dns.com/dns-query` | DNS-over-HTTPS endpoint used to re-resolve hosts on fake-IP networks |
| `NIKTO_MAX_HOSTS` / `ZAP_MAX_HOSTS` | `5` / `3` | Hosts analysed by Nikto / ZAP |
| `TZ` (Docker) | `UTC` | Time zone used in timestamps and reports, e.g. `America/Sao_Paulo` |

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `httpx` module skipped: *"ausente ou é o httpx do Python"* | The Python `httpx` CLI shadows ProjectDiscovery's. Install PD httpx (`scripts/install.sh`) and put it first in `PATH` |
| Every host shows all ports open | A firewall/WAF/tarpit answers every SYN. ECHO trims those hosts to 80/443 and lists them in `hosts/ports_all_open.txt` |
| *"proxy fake-IP (198.18.0.0/15)"* and `ports` skipped | Your network resolves everything to a transparent proxy (common in sandboxes/VPN clients). ECHO re-resolves hosts via DoH, but ports cannot be trusted there: run from a normal network or set `ECHO_FORCE_PORTS=true` |
| `subdomains` shows `crt.sh:0` | crt.sh is often overloaded (HTTP 502). ECHO retries 4×; other sources still run |
| Few subdomains | Add API keys to `~/.config/subfinder/provider-config.yaml` |
| No PDF, only JSON | `reportlab` missing: `apt install python3-reportlab` (or `pip install --user reportlab`) |
| `Permission denied` in `output/` | The container runs as UID 1000: `sudo chown -R 1000:1000 output/` |
| Nuclei `no templates provided` | Templates not downloaded: `nuclei -ut` (done automatically on first run and at image build) |

## Contributing

1. Create a branch, keep changes focused, and update `CHANGELOG.md`.
2. Run the same checks as CI: `shellcheck -x recon.sh entrypoint.sh scripts/install.sh`, `go vet ./api && go test ./api`,
   `ruff check report tests`, and `python3 tests/make_fixture.py /tmp/fx && python3 report/echo_report.py --scan-dir /tmp/fx/recon-example.com-2026-11-25-120000 --lang both`.
3. To bump a tool, edit `scripts/versions.env`, rebuild the image and run a scan against a domain you own.
4. Use `example.com` (and RFC 5737 IPs) in docs, tests and samples — never real client data.

## Legal & ethical use

ECHO is intended for **authorized security assessments** of assets you own or have explicit, written permission to
test. Even "light" scanning can be illegal without authorization, may trigger IDS/IPS and must respect the terms of
the third-party data sources it queries. You are solely responsible for how you use this tool; the authors accept no
liability for misuse or damage. Results are automated, can contain false positives and do not replace a manual
penetration test.

## License

No license file has been chosen yet. Until one is added, all rights are reserved by the author.

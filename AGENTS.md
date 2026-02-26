# AGENTS.md

## Cursor Cloud specific instructions

### Overview

ECHO Advanced Scan Suite is a Docker-based automated security reconnaissance scanner. It has two modes: CLI scan via `recon.sh -d <domain>` and a REST API server (Go, stdlib-only) on port 8080. There are no external databases or message queues.

### Build & Run

Standard commands are documented in the README. Key points:

- **Build**: `docker build -t echo-scanner .` (heavy build — installs ~12 Go-based security tools; takes 4–6 minutes)
- **API mode**: `docker run --rm -p 8080:8080 -v $(pwd)/output:/app/output echo-scanner serve`
- **CLI mode**: `docker run --rm -v $(pwd)/output:/app/output echo-scanner -d <domain>`
- **Go compile check** (local, no Docker): `go build ./api`

### Docker in Cloud VM

Docker requires special setup in the Cursor Cloud VM (nested container environment):

1. Install `fuse-overlayfs` and configure `/etc/docker/daemon.json` with `"storage-driver": "fuse-overlayfs"`.
2. Switch iptables to legacy mode: `update-alternatives --set iptables /usr/sbin/iptables-legacy`.
3. Start dockerd manually: `sudo dockerd &>/tmp/dockerd.log &` (wait ~3s before issuing docker commands).

### Lint & Test

- There is no linter configuration or test suite in the repository.
- **Go vet** can be used for static analysis: `go vet ./api/...`
- Validate the API server compiles: `go build -o /dev/null ./api`

### Gotchas

- **Go version**: `getJS@latest` requires Go >= 1.24. The Dockerfile uses Go 1.25.7.
- **getJS flag change**: The `--list` flag was renamed to `--input` in newer versions of getJS.
- **Nuclei v3 flag change**: `-json` was replaced by `-jsonl` for JSONL output.
- **gau flag change**: `-b` was replaced by `--blacklist`, `-t` by `--threads`.
- **Nikto**: Installed from GitHub (sullo/nikto) instead of the Ubuntu repo, because the repo version (2.1.5) has broken SSL and no JSON output support.
- **pipefail**: The script uses `set -eo pipefail`. All tool invocations in pipelines must be guarded with `|| true` to prevent non-zero exits (e.g. `amass` timeout, `grep` no-match, `gau` errors) from killing the entire script.
- Scans take 15–30 minutes depending on the domain. For quick API verification, just confirm `GET /api/scans` returns JSON after starting the container in `serve` mode.
- The `recon.sh` script hardcodes output to `/app/output`. When running outside Docker, ensure that directory exists or adjust paths.
- Environment variables `MAX_SCAN_MINUTES`, `NIKTO_MAX_HOSTS`, `ZAP_BASELINE_ENABLED` can tune scan behavior (see README).

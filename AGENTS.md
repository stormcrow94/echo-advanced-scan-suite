# AGENTS.md

## Cursor Cloud specific instructions

### Overview

ECHO - Advanced Scan Suite is a Bash CLI security reconnaissance scanner packaged in Docker. The entire application is `recon.sh` orchestrating ~11 Go-based security tools. There are no tests, no web UI, no databases, and no package manager lockfiles.

### Building and running

- **Build:** `sudo docker build -t echo-scanner .` (takes ~5-7 min; compiles Go tools)
- **Run:** `sudo docker run --rm -v $(pwd)/output:/app/output echo-scanner -d <domain>`
- Use `scanme.nmap.org` as a safe test domain (nmap's official test target).
- The scanner requires internet access to query external APIs and resolve DNS.

### Linting

- **Lint:** `shellcheck recon.sh` — only `recon.sh` needs linting; the rest is Docker/config.
- Current shellcheck warnings (SC2002 - useless cat) are pre-existing style issues in the repo.

### Docker in Cloud VM

Docker requires `sudo` in the Cloud VM. The Docker daemon must be started manually:

```
sudo dockerd &>/tmp/dockerd.log &
```

The VM is configured with `fuse-overlayfs` storage driver and `iptables-legacy` for nested container support.

### Known issues

- The Dockerfile pins Go 1.23.4, but `getJS@latest` now requires Go >= 1.24.0 (via `goquery`). The Go version was bumped to 1.24.0 to fix this.
- The `gau` tool's CLI changed: `-b` flag was renamed to `--blacklist`. This causes stage 5 (URL collection from GAU) to fail, but `waybackurls` still works in the same subshell. The script exits at stage 5 due to `set -eo pipefail`.

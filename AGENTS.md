# AGENTS.md

## Overview

ECHO Advanced Scan Suite: `recon.sh` (bash pipeline) + `report/echo_report.py` (PDF/JSON reports, en/pt-BR)
+ `api/` (Go stdlib REST API). Tools are pinned in `scripts/versions.env` and installed by `scripts/install.sh`
(also used by the Dockerfile).

## Build, lint, test

- Image: `docker build -t echo-scanner .` (downloads prebuilt binaries; ~3-5 min).
- Shell: `shellcheck -x recon.sh entrypoint.sh scripts/install.sh`
- Go: `gofmt -l api/ && go vet ./api && go test ./api`
- Python: `ruff check report tests`
- Report smoke test (no network): `python3 tests/make_fixture.py /tmp/fx && python3 report/echo_report.py --scan-dir /tmp/fx/recon-example.com-2026-11-25-120000 --lang both --format both`
- Plan without traffic: `./recon.sh -d example.com --dry-run`

## Gotchas

- Never scan targets without authorization. Use `example.com` and RFC 5737 IPs in tests, docs and samples.
- Do not edit `recon.sh` in place while a scan is running (bash reads the script incrementally); write a copy and `mv` it.
- Sandboxes often resolve every name to a fake-IP proxy (198.18.0.0/15): `recon.sh` detects it and skips `ports`.
- Nuclei templates moved under `http/`, `dns/`, `ssl/`...; validate `-t` paths after a template bump.
- katana `-kf` accepts a single value (`all`, `robotstxt` or `sitemapxml`); tlsx forbids `-san/-cn` together with other probes.
- The container runs as UID 1000 (`recon`); mounted `output/` must be writable by it.

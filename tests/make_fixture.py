#!/usr/bin/env python3
"""Creates a FAKE scan directory for example.com (used by CI and to build samples/).
All hosts, IPs (RFC 5737 documentation ranges) and findings are fictitious."""
import json
import sys
from pathlib import Path

out = Path(sys.argv[1] if len(sys.argv) > 1 else "tests/fixtures") / "recon-example.com-2026-11-25-120000"
for d in ("subdomains", "hosts", "tls", "urls", "js", "vulns"):
    (out / d).mkdir(parents=True, exist_ok=True)

subs = ["example.com", "www.example.com", "api.example.com", "mail.example.com", "dev.example.com",
        "staging.example.com", "vpn.example.com", "old.example.com", "cdn.example.com", "status.example.com"]
(out / "subdomains.txt").write_text("\n".join(subs) + "\n")
ips = {s: f"192.0.2.{i + 10}" for i, s in enumerate(subs)}
resolved = [s for s in subs if s != "old.example.com"]
(out / "hosts" / "resolved.txt").write_text("\n".join(resolved) + "\n")
(out / "hosts" / "dns.json").write_text("\n".join(json.dumps({"host": s, "a": [ips[s]]}) for s in resolved) + "\n")
ports = ["www.example.com:80", "www.example.com:443", "api.example.com:443", "api.example.com:8443",
         "mail.example.com:25", "mail.example.com:443", "mail.example.com:993", "dev.example.com:22",
         "dev.example.com:80", "dev.example.com:3000", "staging.example.com:443", "vpn.example.com:443",
         "example.com:443", "status.example.com:443"]
(out / "hosts" / "ports.txt").write_text("\n".join(ports) + "\n")
(out / "hosts" / "ports_all_open.txt").write_text("cdn.example.com\n")
web = [
    ("https://example.com", 200, "Example Corp", ["Nginx", "HSTS"]),
    ("https://www.example.com", 200, "Example Corp - Home", ["Nginx", "WordPress:6.6", "PHP:8.2"]),
    ("https://api.example.com", 401, "", ["Envoy"]),
    ("https://api.example.com:8443", 200, "Swagger UI", ["Swagger UI", "Java"]),
    ("https://mail.example.com", 200, "Outlook Web App", ["Microsoft Exchange", "IIS:10.0"]),
    ("http://dev.example.com", 200, "Welcome to nginx!", ["Nginx:1.18.0"]),
    ("http://dev.example.com:3000", 200, "Grafana", ["Grafana:9.1.0"]),
    ("https://staging.example.com", 200, "Example Corp (staging)", ["Nginx", "React"]),
    ("https://vpn.example.com", 200, "SSL VPN", ["Fortinet FortiGate"]),
    ("https://status.example.com", 200, "Status", ["Cloudflare"]),
]
(out / "hosts" / "httpx.json").write_text("\n".join(json.dumps(
    {"url": u, "status_code": c, "title": t, "tech": tech, "webserver": tech[0], "a": ["192.0.2.50"]})
    for u, c, t, tech in web) + "\n")
(out / "hosts" / "alive.txt").write_text("\n".join(w[0] for w in web) + "\n")
tls = [
    {"host": "example.com", "port": "443", "tls_version": "tls13", "subject_cn": "example.com",
     "issuer_org": ["Let's Encrypt"], "not_after": "2027-02-01T00:00:00Z"},
    {"host": "staging.example.com", "port": "443", "tls_version": "tls12", "subject_cn": "staging.example.com",
     "issuer_org": ["Example Internal CA"], "not_after": "2026-08-01T00:00:00Z", "expired": True,
     "self_signed": True},
    {"host": "vpn.example.com", "port": "443", "tls_version": "tls11", "subject_cn": "fortigate",
     "issuer_org": ["Fortinet"], "not_after": "2030-01-01T00:00:00Z", "mismatched": True, "untrusted": True},
    {"host": "mail.example.com", "port": "443", "tls_version": "tls12", "subject_cn": "mail.example.com",
     "issuer_org": ["DigiCert Inc"], "not_after": "2027-05-10T00:00:00Z"},
]
(out / "tls" / "tlsx.json").write_text("\n".join(json.dumps(x) for x in tls) + "\n")
(out / "urls.txt").write_text("\n".join(f"https://www.example.com/page/{i}?id={i}" for i in range(120)) + "\n")
(out / "urls" / "crawl.txt").write_text("\n".join(f"https://www.example.com/blog/{i}" for i in range(40)) + "\n")
(out / "js" / "js_urls.txt").write_text("https://www.example.com/static/app.js\nhttps://staging.example.com/main.js\n")
(out / "js" / "endpoints.txt").write_text("/api/v1/users\n/api/v1/orders\n/graphql\n/internal/health\n")


def nf(tid, sev, name, at, desc="", ref=None, tags="", ext=None, rem=""):
    return {"template-id": tid, "info": {"name": name, "severity": sev, "description": desc, "reference": ref or [],
            "tags": tags, "remediation": rem}, "matched-at": at, "host": at, "extracted-results": ext or [],
            "timestamp": "2026-11-25T12:20:00-03:00"}


nuclei = [
    nf("git-config", "medium", "Git Configuration - Detect", "https://staging.example.com/.git/config",
       "Git configuration was detected via the pattern /.git/config and log file on passed URLs.",
       ["https://owasp.org/www-project-top-ten/"], "config,git,exposure",
       rem="Block access to /.git on the web server and remove the repository from the web root."),
    nf("grafana-detect", "info", "Grafana Detect", "http://dev.example.com:3000/login", tags="tech,grafana",
       ext=["9.1.0"]),
    nf("swagger-api", "info", "Public Swagger API - Detect", "https://api.example.com:8443/swagger-ui/index.html",
       tags="exposure,api,swagger"),
    nf("http-missing-security-headers", "info", "HTTP Missing Security Headers", "https://www.example.com",
       tags="misconfig,headers", ext=["content-security-policy", "permissions-policy"]),
    nf("wordpress-detect", "info", "WordPress Detect", "https://www.example.com", tags="tech,wordpress", ext=["6.6"]),
    nf("exposed-panel-fortinet", "info", "Fortinet FortiGate SSL VPN Panel - Detect", "https://vpn.example.com",
       tags="panel,fortinet"),
    nf("nginx-version", "low", "Nginx version disclosure", "http://dev.example.com", tags="tech,nginx",
       ext=["nginx/1.18.0"], rem="Set server_tokens off."),
    nf("dns-caa", "info", "CAA Record", "example.com", tags="dns,caa"),
]
(out / "vulns" / "nuclei.json").write_text("\n".join(json.dumps(x) for x in nuclei) + "\n")
mods = [("subdomains", "ok", 74, "10 subdomínios (subfinder:9 findomain:8 crt.sh:7)"),
        ("dns", "ok", 12, "9 hosts resolvidos"),
        ("ports", "ok", 95, "14 host:porta abertos (scan c, 1 host(s) respondem em ≥80% das portas (filtrados p/ 80,443))"),
        ("web", "ok", 33, "10 URLs web ativas"), ("tls", "ok", 8, "4 certificados analisados"),
        ("urls", "ok", 41, "120 URLs (limite 20000)"), ("crawl", "ok", 300, "40 URLs rastreadas"),
        ("js", "ok", 15, "2 arquivos JS, 4 endpoints"), ("nuclei", "ok", 610, "8 achados")]
(out / "status.json").write_text(json.dumps({
    "id": out.name, "domain": "example.com", "profile": "standard", "version": "2026.11", "rate_limit": 20,
    "top_ports": 100, "started_at": "2026-11-25T12:00:00-03:00", "finished_at": "2026-11-25T12:20:28-03:00",
    "status": "completed",
    "modules": [{"name": n, "status": s, "seconds": t, "detail": d} for n, s, t, d in mods]}, indent=2))
print(out)

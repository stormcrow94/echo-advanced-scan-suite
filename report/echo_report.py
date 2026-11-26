#!/usr/bin/env python3
"""ECHO Advanced Scan Suite - report generator.

Reads a scan directory produced by recon.sh and writes:
  * report-<lang>.json  machine-readable export (schema: docs/REPORT_SCHEMA.md)
  * report-<lang>.pdf   formatted report (requires reportlab)

Usage:
  python3 report/echo_report.py --scan-dir output/recon-example.com-2026-01-01-120000 \
      --lang pt-BR|en|both --format pdf|json|both [--out-dir DIR] \
      [--title T] [--client C] [--author A] [--logo FILE]
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from i18n import t  # noqa: E402

SCHEMA_VERSION = "1.0"
GENERATOR_VERSION = "2026.11"
SEVERITIES = ["critical", "high", "medium", "low", "info", "unknown"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}
REPO_ROOT = Path(__file__).resolve().parent.parent


# --------------------------------------------------------------------------- #
# Loading helpers
# --------------------------------------------------------------------------- #
def read_lines(path: Path) -> list[str]:
    try:
        return [ln.strip() for ln in path.read_text(errors="replace").splitlines() if ln.strip()]
    except OSError:
        return []


def read_jsonl(path: Path) -> list[dict]:
    out = []
    for ln in read_lines(path):
        try:
            v = json.loads(ln)
        except json.JSONDecodeError:
            continue
        if isinstance(v, dict):
            out.append(v)
    return out


def read_json(path: Path):
    try:
        return json.loads(path.read_text(errors="replace"))
    except (OSError, json.JSONDecodeError):
        return None


def parse_ts(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s)
    except ValueError:
        return None


def fmt_ts(s: str | None) -> str:
    d = parse_ts(s)
    if not d:
        return "-"
    if d.tzinfo is None:
        return d.strftime("%Y-%m-%d %H:%M:%S")
    off = d.utcoffset()
    mins = int(off.total_seconds() // 60) if off else 0
    sign = "+" if mins >= 0 else "-"
    return d.strftime("%Y-%m-%d %H:%M:%S") + f" (UTC{sign}{abs(mins)//60:02d}:{abs(mins)%60:02d})"


def fmt_duration(sec: int | None) -> str:
    if sec is None:
        return "-"
    h, rem = divmod(int(sec), 3600)
    m, s = divmod(rem, 60)
    return f"{h}h {m:02d}m {s:02d}s" if h else f"{m}m {s:02d}s"


# --------------------------------------------------------------------------- #
# Model
# --------------------------------------------------------------------------- #
def nuclei_findings(scan: Path) -> list[dict]:
    out = []
    for r in read_jsonl(scan / "vulns" / "nuclei.json"):
        info = r.get("info") or {}
        refs = info.get("reference") or []
        if isinstance(refs, str):
            refs = [refs]
        tags = info.get("tags") or []
        if isinstance(tags, str):
            tags = [x.strip() for x in tags.split(",") if x.strip()]
        sev = str(info.get("severity") or "unknown").lower()
        evidence = r.get("extracted-results") or []
        if not evidence and r.get("matcher-name"):
            evidence = [r["matcher-name"]]
        out.append({
            "id": r.get("template-id") or "nuclei",
            "source": "nuclei",
            "severity": sev if sev in SEV_RANK else "unknown",
            "name": info.get("name") or r.get("template-id") or "nuclei",
            "target": r.get("matched-at") or r.get("host") or "",
            "description": (info.get("description") or "").strip(),
            "remediation": (info.get("remediation") or "").strip(),
            "references": [x for x in refs if x][:5],
            "tags": tags,
            "evidence": [str(x) for x in evidence][:10],
            "timestamp": r.get("timestamp"),
        })
    return out


def nikto_findings(scan: Path) -> list[dict]:
    out = []
    for f in sorted((scan / "vulns").glob("nikto_*.json")):
        data = read_json(f)
        if data is None:
            continue
        reports = data if isinstance(data, list) else [data]
        for rep in reports:
            if not isinstance(rep, dict):
                continue
            host = rep.get("host") or ""
            port = rep.get("port") or ""
            for v in rep.get("vulnerabilities") or []:
                url = v.get("url") or ""
                refs = v.get("references") or []
                if isinstance(refs, str):
                    refs = [refs] if refs else []
                out.append({
                    "id": f"nikto-{v.get('id', '')}",
                    "source": "nikto",
                    "severity": "info",
                    "name": (v.get("msg") or "").strip()[:200] or "Nikto",
                    "target": f"{host}:{port}{url}" if host else url,
                    "description": (v.get("msg") or "").strip(),
                    "remediation": "",
                    "references": refs[:5],
                    "tags": ["nikto"],
                    "evidence": [f"{v.get('method', 'GET')} {url}"],
                    "timestamp": None,
                })
    return out


def zap_findings(scan: Path) -> list[dict]:
    riskmap = {"0": "info", "1": "low", "2": "medium", "3": "high"}
    out = []
    for f in sorted((scan / "vulns").glob("zap_*.json")):
        data = read_json(f) or {}
        for site in data.get("site", []) or []:
            for a in site.get("alerts", []) or []:
                out.append({
                    "id": f"zap-{a.get('pluginid', '')}",
                    "source": "zap",
                    "severity": riskmap.get(str(a.get("riskcode")), "unknown"),
                    "name": a.get("name") or a.get("alert") or "ZAP alert",
                    "target": site.get("@name", ""),
                    "description": _strip_html(a.get("desc", "")),
                    "remediation": _strip_html(a.get("solution", "")),
                    "references": [x for x in _strip_html(a.get("reference", "")).split() if x.startswith("http")][:5],
                    "tags": ["zap"],
                    "evidence": [i.get("uri", "") for i in (a.get("instances") or [])[:5]],
                    "timestamp": None,
                })
    return out


def _strip_html(s: str) -> str:
    import re
    return re.sub(r"<[^>]+>", " ", s or "").strip()


def tls_assets_and_findings(scan: Path, lang: str) -> tuple[list[dict], list[dict]]:
    assets, findings = [], []
    for r in read_jsonl(scan / "tls" / "tlsx.json"):
        host = r.get("host") or r.get("ip") or ""
        port = str(r.get("port") or "443")
        flags = []
        ver = (r.get("tls_version") or r.get("version") or "").lower()
        checks = [
            ("expired", "high", "tls_expired"),
            ("self_signed", "medium", "tls_self"),
            ("mismatched", "medium", "tls_mismatch"),
            ("untrusted", "medium", "tls_untrusted"),
        ]
        for key, sev, k in checks:
            if r.get(key):
                flags.append(t(lang, f"flag_{key}"))
                findings.append(_tls_finding(lang, k, sev, f"{host}:{port}", r))
        if ver in ("tls10", "tls11", "ssl30"):
            flags.append(t(lang, "flag_old_tls"))
            findings.append(_tls_finding(lang, "tls_old", "medium", f"{host}:{port}", r))
        assets.append({
            "host": host,
            "port": port,
            "tls_version": ver,
            "subject_cn": r.get("subject_cn") or "",
            "subject_an": r.get("subject_an") or [],
            "issuer": r.get("issuer_org") or r.get("issuer_cn") or [],
            "not_after": r.get("not_after") or "",
            "expired": bool(r.get("expired")),
            "self_signed": bool(r.get("self_signed")),
            "mismatched": bool(r.get("mismatched")),
            "untrusted": bool(r.get("untrusted")),
            "flags": flags,
        })
    return assets, findings


def _tls_finding(lang, key, sev, target, r):
    return {
        "id": f"echo-{key.replace('_', '-')}",
        "source": "tlsx",
        "severity": sev,
        "name": t(lang, f"{key}_name"),
        "target": target,
        "description": t(lang, f"{key}_desc"),
        "remediation": t(lang, "tls_fix"),
        "references": [],
        "tags": ["tls"],
        "evidence": [f"CN={r.get('subject_cn', '')}", f"not_after={r.get('not_after', '')}"],
        "timestamp": r.get("timestamp"),
    }


def localize_modules(mods: list[dict], lang: str, n: dict) -> list[dict]:
    """Rebuilds each module's result text in the report language (recon.sh logs it in pt-BR)."""
    out = []
    for m in mods:
        m = dict(m)
        name, st = m.get("name", ""), m.get("status", "")
        m["detail_raw"] = m.get("detail", "")
        if st in ("ok", "empty"):
            if name == "js":
                m["detail"] = t(lang, "md_js", a=n["js_files"], b=n["js_endpoints"])
            elif name == "ports" and n["all_open"]:
                m["detail"] = t(lang, "md_ports", n=n["ports"]) + "; " + t(lang, "md_all_open", n=n["all_open"])
            elif name in n:
                m["detail"] = t(lang, f"md_{name}", n=n[name])
        elif lang == "en":
            d = m["detail_raw"]
            for a, b in (("ferramenta ausente", "missing tool"), ("orçamento de tempo", "time budget"),
                         ("esgotado", "exhausted"), ("erro do nuclei", "nuclei error"),
                         ("zap-baseline.py ausente ou orçamento esgotado", "zap-baseline.py missing or time budget exhausted")):
                d = d.replace(a, b)
            m["detail"] = d
        out.append(m)
    return out


def build_model(scan: Path, lang: str, title: str | None, client: str | None,
                author: str | None) -> dict:
    status = read_json(scan / "status.json") or {}
    sid = status.get("id") or scan.name
    target = status.get("domain") or sid.removeprefix("recon-").rsplit("-", 4)[0]
    started, finished = status.get("started_at"), status.get("finished_at")
    ds, df = parse_ts(started), parse_ts(finished)
    duration = int((df - ds).total_seconds()) if ds and df else None

    dns = []
    for r in read_jsonl(scan / "hosts" / "dns.json"):
        dns.append({"host": r.get("host", ""), "a": r.get("a") or [], "aaaa": r.get("aaaa") or [],
                    "cname": r.get("cname") or []})
    resolved_set = set(read_lines(scan / "hosts" / "resolved.txt"))
    if dns:
        dns = [d for d in dns if d["a"] or d["aaaa"] or d["host"] in resolved_set]
    else:
        dns = [{"host": h, "a": [], "aaaa": [], "cname": []} for h in sorted(resolved_set)]

    ports = []
    for ln in read_lines(scan / "hosts" / "ports.txt"):
        host, _, port = ln.rpartition(":")
        if host and port.isdigit():
            ports.append({"host": host, "port": int(port)})
    ports.sort(key=lambda p: (p["host"], p["port"]))

    web = []
    for r in read_jsonl(scan / "hosts" / "httpx.json"):
        web.append({
            "url": r.get("url", ""), "status_code": r.get("status_code"),
            "title": (r.get("title") or "").strip(), "webserver": r.get("webserver") or "",
            "technologies": r.get("tech") or [], "ip": (r.get("a") or [r.get("host_ip") or r.get("ip") or ""])[0],
            "cdn": r.get("cdn_name") or ("yes" if r.get("cdn") else ""),
            "location": r.get("location") or "",
        })
    web.sort(key=lambda w: w["url"])

    tls_assets, tls_findings = tls_assets_and_findings(scan, lang)
    findings = nuclei_findings(scan) + nikto_findings(scan) + zap_findings(scan) + tls_findings
    findings.sort(key=lambda f: (SEV_RANK.get(f["severity"], 9), f["name"], f["target"]))

    sev = {s: 0 for s in SEVERITIES}
    for f in findings:
        sev[f["severity"]] = sev.get(f["severity"], 0) + 1
    risk = next((s for s in SEVERITIES[:5] if sev[s] > 0), "none")

    hist = read_lines(scan / "urls.txt")
    crawl = read_lines(scan / "urls" / "crawl.txt")
    js_files = read_lines(scan / "js" / "js_urls.txt")
    endpoints = read_lines(scan / "js" / "endpoints.txt")
    subs = read_lines(scan / "subdomains.txt")
    all_open = read_lines(scan / "hosts" / "ports_all_open.txt")

    return {
        "schema": "echo-report",
        "schema_version": SCHEMA_VERSION,
        "generator": {"name": "ECHO Advanced Scan Suite", "version": GENERATOR_VERSION},
        "language": lang,
        "report": {
            "title": title or t(lang, "default_title"),
            "client": client or "",
            "author": author or "",
            "generated_at": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
        },
        "scan": {
            "id": sid, "target": target, "profile": status.get("profile", ""),
            "status": status.get("status", "unknown"), "started_at": started, "finished_at": finished,
            "duration_seconds": duration, "rate_limit": status.get("rate_limit"),
            "top_ports": status.get("top_ports"), "error": status.get("error"),
            "tool_version": status.get("version", ""),
        },
        "modules": localize_modules(status.get("modules", []), lang, {
            "subdomains": len(subs), "dns": len(dns), "ports": len(ports), "all_open": len(all_open),
            "web": len(web), "tls": len(tls_assets), "urls": len(hist), "crawl": len(crawl),
            "js_files": len(js_files), "js_endpoints": len(endpoints),
            "nuclei": sum(1 for f in findings if f["source"] == "nuclei"),
            "nikto": sum(1 for f in findings if f["source"] == "nikto"),
            "zap": sum(1 for f in findings if f["source"] == "zap")}),
        "summary": {
            "subdomains": len(subs), "resolved_hosts": len(dns), "open_ports": len(ports),
            "web_services": len(web), "urls_historical": len(hist), "urls_crawled": len(crawl),
            "js_files": len(js_files), "js_endpoints": len(endpoints), "tls_certificates": len(tls_assets),
            "hosts_all_ports_open": len(all_open),
            "findings_total": len(findings), "severity": sev, "risk_rating": risk,
        },
        "findings": findings,
        "assets": {"subdomains": subs, "dns": dns, "ports": ports, "ports_all_open_hosts": all_open,
                   "web": web, "tls": tls_assets},
        "urls": {"historical": hist, "crawled": crawl},
        "javascript": {"files": js_files, "endpoints": endpoints},
    }


# --------------------------------------------------------------------------- #
# PDF rendering
# --------------------------------------------------------------------------- #
SEV_COLORS = {
    "critical": "#7B1FA2", "high": "#D32F2F", "medium": "#F57C00",
    "low": "#FBC02D", "info": "#1E88E5", "unknown": "#757575", "none": "#2E7D32",
}
ACCENT = "#00E5A8"
DARK = "#0B1220"
MUTED = "#5B6577"


def render_pdf(model: dict, out_path: Path, logo: str | None) -> None:
    from xml.sax.saxutils import escape

    from reportlab.graphics.charts.barcharts import HorizontalBarChart
    from reportlab.graphics.shapes import Drawing
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    from reportlab.platypus import (
        Image,
        KeepTogether,
        PageBreak,
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )

    lang = model["language"]
    L = lambda k, **kw: t(lang, k, **kw)

    # Fonts: DejaVu (full Unicode) when available, Helvetica otherwise
    font, font_b, mono = "Helvetica", "Helvetica-Bold", "Courier"
    for base in ("/usr/share/fonts/truetype/dejavu", "/usr/share/fonts/dejavu"):
        if os.path.exists(f"{base}/DejaVuSans.ttf"):
            pdfmetrics.registerFont(TTFont("DejaVu", f"{base}/DejaVuSans.ttf"))
            pdfmetrics.registerFont(TTFont("DejaVu-Bold", f"{base}/DejaVuSans-Bold.ttf"))
            if os.path.exists(f"{base}/DejaVuSansMono.ttf"):
                pdfmetrics.registerFont(TTFont("DejaVuMono", f"{base}/DejaVuSansMono.ttf"))
                mono = "DejaVuMono"
            font, font_b = "DejaVu", "DejaVu-Bold"
            from reportlab.lib.fonts import addMapping
            addMapping("DejaVu", 0, 0, "DejaVu")
            addMapping("DejaVu", 1, 0, "DejaVu-Bold")
            addMapping("DejaVu", 0, 1, "DejaVu")
            addMapping("DejaVu", 1, 1, "DejaVu-Bold")
            break

    ss = getSampleStyleSheet()
    body = ParagraphStyle("body", parent=ss["BodyText"], fontName=font, fontSize=9.5, leading=13.5)
    small = ParagraphStyle("small", parent=body, fontSize=8, leading=10.5, textColor=colors.HexColor(MUTED))
    cell = ParagraphStyle("cell", parent=body, fontSize=8, leading=10)
    cellmono = ParagraphStyle("cellmono", parent=cell, fontName=mono, fontSize=7.3, leading=9.2)
    h1 = ParagraphStyle("h1", parent=body, fontName=font_b, fontSize=16, leading=20, spaceBefore=4,
                        spaceAfter=8, textColor=colors.HexColor(DARK))
    h2 = ParagraphStyle("h2", parent=body, fontName=font_b, fontSize=11.5, leading=15, spaceBefore=10,
                        spaceAfter=5, textColor=colors.HexColor("#0E3B43"))
    P = lambda s, st=body: Paragraph(s, st)
    E = lambda s: escape(str(s if s is not None else ""))

    scan, summ, rep = model["scan"], model["summary"], model["report"]
    W, H = A4
    margin = 16 * mm
    content_w = W - 2 * margin
    banner = REPO_ROOT / "assets" / "banner.png"

    def on_page(c, doc):
        c.saveState()
        if doc.page == 1:
            c.setFillColor(colors.HexColor(DARK))
            c.rect(0, 0, W, H, stroke=0, fill=1)
        else:
            c.setStrokeColor(colors.HexColor(ACCENT))
            c.setLineWidth(1.2)
            c.line(margin, H - 11 * mm, W - margin, H - 11 * mm)
            c.setFont(font_b, 8)
            c.setFillColor(colors.HexColor(DARK))
            c.drawString(margin, H - 9.5 * mm, "ECHO · Advanced Scan Suite")
            c.setFont(font, 8)
            c.drawRightString(W - margin, H - 9.5 * mm, f"{scan['target']} · {L('confidential')}")
            c.setFillColor(colors.HexColor(MUTED))
            c.drawString(margin, 9 * mm, rep["title"][:90])
            c.drawRightString(W - margin, 9 * mm, f"{L('page')} {doc.page}")
        c.restoreState()

    story = []
    # ---------------- Cover ----------------
    cover_w = W - 2 * margin
    if banner.exists():
        src = str(banner)
        try:  # re-encode as JPEG to keep the PDF small
            import io

            from PIL import Image as PILImage
            buf = io.BytesIO()
            PILImage.open(banner).convert("RGB").save(buf, "JPEG", quality=85)
            buf.seek(0)
            src = buf
        except ImportError:
            pass
        story.append(Image(src, width=cover_w, height=cover_w * 400 / 1280))
    story.append(Spacer(1, 18 * mm))
    cover_title = ParagraphStyle("ct", parent=h1, fontSize=24, leading=30, textColor=colors.white)
    cover_sub = ParagraphStyle("cs", parent=body, fontSize=12, leading=16, textColor=colors.HexColor(ACCENT))
    cover_txt = ParagraphStyle("cx", parent=body, fontSize=10, leading=15, textColor=colors.HexColor("#C9D3E3"))
    if logo and os.path.exists(logo):
        try:
            img = Image(logo)
            ratio = img.imageHeight / float(img.imageWidth or 1)
            lw = 38 * mm
            img.drawWidth, img.drawHeight = lw, lw * ratio
            img.hAlign = "LEFT"
            story += [img, Spacer(1, 6 * mm)]
        except Exception:
            pass
    story.append(P(E(rep["title"]), cover_title))
    story.append(P(E(scan["target"]), cover_sub))
    story.append(Spacer(1, 10 * mm))
    meta = [(L("target"), scan["target"]), (L("client"), rep["client"] or "-"), (L("author"), rep["author"] or "-"),
            (L("profile"), scan["profile"]), (L("started"), fmt_ts(scan["started_at"])),
            (L("finished"), fmt_ts(scan["finished_at"])), (L("duration"), fmt_duration(scan["duration_seconds"])),
            (L("generated"), fmt_ts(rep["generated_at"])), (L("scan_id"), scan["id"])]
    mt = Table([[P(f"<b>{E(k)}</b>", cover_txt), P(E(v), cover_txt)] for k, v in meta],
               colWidths=[40 * mm, cover_w - 40 * mm])
    mt.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("BOTTOMPADDING", (0, 0), (-1, -1), 2)]))
    story.append(mt)
    story.append(Spacer(1, 14 * mm))
    risk = summ["risk_rating"]
    badge = Table([[P(f"<b>{L('overall_risk')}: {E(L('risk_' + risk)).upper()}</b>",
                      ParagraphStyle("rb", parent=body, fontSize=12, textColor=colors.white, alignment=TA_CENTER))]],
                  colWidths=[80 * mm], rowHeights=[12 * mm])
    badge.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(SEV_COLORS.get(risk, MUTED))),
                               ("VALIGN", (0, 0), (-1, -1), "MIDDLE")]))
    badge.hAlign = "LEFT"
    story.append(badge)
    story.append(Spacer(1, 10 * mm))
    story.append(P(f"<b>{L('confidential')}</b> · " + E(L("disclaimer")), ParagraphStyle(
        "cd", parent=small, textColor=colors.HexColor("#8A96AB"))))
    story.append(PageBreak())

    def std_table(data, widths, header=True, zebra=True):
        tb = Table(data, colWidths=widths, repeatRows=1 if header else 0)
        style = [("FONTNAME", (0, 0), (-1, -1), font), ("FONTSIZE", (0, 0), (-1, -1), 8),
                 ("VALIGN", (0, 0), (-1, -1), "TOP"), ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#D5DBE5")),
                 ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3)]
        if header:
            style += [("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(DARK)),
                      ("TEXTCOLOR", (0, 0), (-1, 0), colors.white)]
        if zebra:
            for i in range(1 if header else 0, len(data)):
                if i % 2 == 0:
                    style.append(("BACKGROUND", (0, i), (-1, i), colors.HexColor("#F4F7FB")))
        tb.setStyle(TableStyle(style))
        return tb

    hdr = ParagraphStyle("hdr", parent=cell, fontName=font_b, textColor=colors.white)
    H_ = lambda s: P(E(s), hdr)

    # ---------------- 1. Executive summary ----------------
    story.append(P(L("toc_exec"), h1))
    story.append(P(L("exec_intro", target=E(scan["target"]), profile=E(scan["profile"]))))
    story.append(Spacer(1, 5 * mm))
    kpis = [("kpi_subdomains", summ["subdomains"]), ("kpi_resolved", summ["resolved_hosts"]),
            ("kpi_ports", summ["open_ports"]), ("kpi_web", summ["web_services"]),
            ("kpi_urls", summ["urls_historical"] + summ["urls_crawled"]), ("kpi_js", summ["js_files"]),
            ("kpi_endpoints", summ["js_endpoints"]), ("kpi_findings", summ["findings_total"])]
    kv = ParagraphStyle("kv", parent=body, fontName=font_b, fontSize=17, leading=20, alignment=TA_CENTER,
                        textColor=colors.HexColor(DARK))
    kl = ParagraphStyle("kl", parent=small, alignment=TA_CENTER)
    cells = [[P(f"{v}", kv), P(E(L(k)), kl)] for k, v in kpis]
    rows = []
    for i in range(0, 8, 4):
        rows.append([Table([[c[0]], [c[1]]], colWidths=[content_w / 4 - 6]) for c in cells[i:i + 4]])
    kt = Table(rows, colWidths=[content_w / 4] * 4)
    kt.setStyle(TableStyle([("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#D5DBE5")),
                            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D5DBE5")),
                            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F4F7FB")),
                            ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6)]))
    story.append(kt)

    story.append(P(L("sev_dist"), h2))
    sev = summ["severity"]
    sev_rows = [[H_(L("severity")), H_(L("count"))]]
    for s in SEVERITIES:
        sev_rows.append([P(f'<font color="{SEV_COLORS[s]}">■</font> {E(L("sev_" + s))}', cell), P(str(sev[s]), cell)])
    st = std_table(sev_rows, [40 * mm, 18 * mm])
    d = Drawing(content_w - 64 * mm, 50 * mm)
    ch = HorizontalBarChart()
    ch.x, ch.y, ch.width, ch.height = 52, 5, content_w - 64 * mm - 70, 45 * mm
    vals = [sev[s] for s in reversed(SEVERITIES)]
    ch.data = [vals]
    ch.categoryAxis.categoryNames = [L("sev_" + s) for s in reversed(SEVERITIES)]
    ch.categoryAxis.labels.fontName = font
    ch.categoryAxis.labels.fontSize = 7.5
    ch.valueAxis.valueMin = 0
    ch.valueAxis.valueMax = max(vals + [1]) * 1.15
    ch.valueAxis.labels.fontName = font
    ch.valueAxis.labels.fontSize = 7
    ch.bars.strokeColor = None
    for i, s in enumerate(reversed(SEVERITIES)):
        ch.bars[(0, i)].fillColor = colors.HexColor(SEV_COLORS[s])
    d.add(ch)
    two = Table([[st, d]], colWidths=[62 * mm, content_w - 62 * mm])
    two.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP")]))
    story.append(two)

    story.append(P(L("status"), h2))
    meta2 = [[P(f"<b>{E(L('target'))}</b>", cell), P(E(scan["target"]), cell),
              P(f"<b>{E(L('profile'))}</b>", cell), P(E(scan["profile"]), cell)],
             [P(f"<b>{E(L('started'))}</b>", cell), P(E(fmt_ts(scan["started_at"])), cell),
              P(f"<b>{E(L('finished'))}</b>", cell), P(E(fmt_ts(scan["finished_at"])), cell)],
             [P(f"<b>{E(L('duration'))}</b>", cell), P(E(fmt_duration(scan["duration_seconds"])), cell),
              P(f"<b>{E(L('rate_limit'))}</b>", cell), P(f"{E(scan['rate_limit'])} {L('req_s')}", cell)]]
    story.append(std_table(meta2, [26 * mm, content_w / 2 - 26 * mm, 26 * mm, content_w / 2 - 26 * mm],
                           header=False, zebra=False))

    # ---------------- 2. Modules ----------------
    story.append(P(L("toc_modules"), h1))
    mrows = [[H_(L("module")), H_(L("status")), H_(L("seconds")), H_(L("detail"))]]
    mcol = {"ok": "#2E7D32", "empty": "#757575", "skipped": "#F57C00", "failed": "#D32F2F"}
    for m in model["modules"]:
        stt = m.get("status", "")
        mrows.append([P(E(L("mod_" + m.get("name", ""))), cell),
                      P(f'<font color="{mcol.get(stt, MUTED)}"><b>{E(L("mod_status_" + stt))}</b></font>', cell),
                      P(fmt_duration(m.get("seconds")), cell), P(E(m.get("detail", "")), cell)])
    story.append(std_table(mrows, [42 * mm, 20 * mm, 18 * mm, content_w - 80 * mm]))

    # ---------------- 3. Findings ----------------
    story.append(PageBreak())
    story.append(P(L("toc_findings"), h1))
    findings = model["findings"]
    if not findings:
        story.append(P(L("no_findings")))
    else:
        story.append(P(L("findings_intro"), small))
        story.append(Spacer(1, 3 * mm))
        frows = [[H_(L("severity")), H_(L("finding")), H_(L("location")), H_(L("source"))]]
        style_extra = []
        limit = 400
        for i, f in enumerate(findings[:limit], start=1):
            frows.append([P(f'<b>{E(L("sev_" + f["severity"]))}</b>', ParagraphStyle(
                f"s{i}", parent=cell, textColor=colors.white)), P(E(f["name"]), cell),
                P(E(f["target"]), cellmono), P(E(f["source"]), cell)])
            style_extra.append(("BACKGROUND", (0, i), (0, i), colors.HexColor(SEV_COLORS.get(f["severity"], MUTED))))
        ft = std_table(frows, [23 * mm, 60 * mm, content_w - 99 * mm, 16 * mm])
        ft.setStyle(TableStyle(style_extra))
        story.append(ft)
        if len(findings) > limit:
            story.append(P(L("truncated", shown=limit, total=len(findings)), small))
        detailed = [f for f in findings if f["severity"] in ("critical", "high", "medium")]
        if detailed:
            story.append(P(L("details_title"), h2))
            for f in detailed[:60]:
                blk = [P(f'<font color="{SEV_COLORS[f["severity"]]}"><b>[{E(L("sev_" + f["severity"]))}]</b></font> '
                         f'<b>{E(f["name"])}</b> <font color="{MUTED}">({E(f["id"])})</font>', body),
                       P(f"<b>{E(L('location'))}:</b> <font name='{mono}'>{E(f['target'])}</font>", cell)]
                if f.get("description"):
                    blk.append(P(f"<b>{E(L('description'))}:</b> {E(f['description'][:900])}", cell))
                if f.get("remediation"):
                    blk.append(P(f"<b>{E(L('remediation'))}:</b> {E(f['remediation'][:600])}", cell))
                if f.get("evidence"):
                    blk.append(P(f"<b>{E(L('evidence'))}:</b> <font name='{mono}'>{E(', '.join(f['evidence'])[:400])}</font>", cell))
                if f.get("references"):
                    blk.append(P(f"<b>{E(L('references'))}:</b> " + "<br/>".join(E(r) for r in f["references"][:4]), small))
                blk.append(Spacer(1, 3 * mm))
                story.append(KeepTogether(blk))

    # ---------------- 4. Attack surface ----------------
    story.append(PageBreak())
    story.append(P(L("toc_assets"), h1))
    assets = model["assets"]

    story.append(P(f"{L('web_services')} ({len(assets['web'])})", h2))
    if assets["web"]:
        wrows = [[H_(L("url")), H_(L("code")), H_(L("title")), H_(L("technologies"))]]
        for w in assets["web"][:150]:
            wrows.append([P(E(w["url"]), cellmono), P(E(w["status_code"]), cell), P(E(w["title"][:80]), cell),
                          P(E(", ".join(w["technologies"][:8]) or w["webserver"]), cell)])
        story.append(std_table(wrows, [62 * mm, 13 * mm, 45 * mm, content_w - 120 * mm]))
        if len(assets["web"]) > 150:
            story.append(P(L("truncated", shown=150, total=len(assets["web"])), small))
    else:
        story.append(P(L("none"), small))

    story.append(P(f"{L('open_ports')} ({len(assets['ports'])})", h2))
    if assets["ports"]:
        by_host: dict[str, list[int]] = {}
        for p in assets["ports"]:
            by_host.setdefault(p["host"], []).append(p["port"])
        prows = [[H_(L("host")), H_(L("port"))]]
        for host, plist in sorted(by_host.items())[:200]:
            prows.append([P(E(host), cellmono), P(E(", ".join(str(x) for x in sorted(set(plist)))), cell)])
        story.append(std_table(prows, [90 * mm, content_w - 90 * mm]))
    else:
        story.append(P(L("none"), small))
    if assets.get("ports_all_open_hosts"):
        story.append(Spacer(1, 2 * mm))
        story.append(P(L("all_open_note", n=len(assets["ports_all_open_hosts"])) + " <font name='" + mono + "'>"
                       + E(", ".join(assets["ports_all_open_hosts"][:40])) + "</font>", small))

    story.append(P(f"{L('tls_certs')} ({len(assets['tls'])})", h2))
    if assets["tls"]:
        trows = [[H_(L("host")), H_(L("tls_version")), H_(L("issuer")), H_(L("expires")), H_(L("flags"))]]
        for c in assets["tls"][:150]:
            issuer = c["issuer"] if isinstance(c["issuer"], str) else ", ".join(c["issuer"] or [])
            fl = ", ".join(c["flags"]) or "✓"
            trows.append([P(E(f"{c['host']}:{c['port']}"), cellmono), P(E(c["tls_version"]), cell),
                          P(E(issuer[:40]), cell), P(E(c["not_after"][:10]), cell),
                          P(f'<font color="{"#D32F2F" if c["flags"] else "#2E7D32"}">{E(fl)}</font>', cell)])
        story.append(std_table(trows, [60 * mm, 14 * mm, 44 * mm, 22 * mm, content_w - 140 * mm]))
    else:
        story.append(P(L("none"), small))

    story.append(P(f"{L('subdomain_list')} ({len(assets['subdomains'])})", h2))
    subs = assets["subdomains"][:300]
    if subs:
        ncol = 3
        per = (len(subs) + ncol - 1) // ncol
        cols = [subs[i * per:(i + 1) * per] for i in range(ncol)]
        srows = [[P(E(cols[c][r]) if r < len(cols[c]) else "", cellmono) for c in range(ncol)] for r in range(per)]
        story.append(std_table(srows, [content_w / ncol] * ncol, header=False))
        if len(assets["subdomains"]) > 300:
            story.append(P(L("truncated", shown=300, total=len(assets["subdomains"])), small))

    eps = model["javascript"]["endpoints"]
    if eps:
        story.append(P(f"{L('endpoints_sample')} ({len(eps)})", h2))
        story.append(P("<br/>".join(E(e[:120]) for e in eps[:60]), cellmono))
        if len(eps) > 60:
            story.append(P(L("truncated", shown=60, total=len(eps)), small))

    # ---------------- 5. Appendix ----------------
    story.append(PageBreak())
    story.append(P(L("toc_appendix"), h1))
    story.append(P(E(L("methodology"))))
    story.append(Spacer(1, 4 * mm))
    story.append(P(f"<b>{E(L('disclaimer'))}</b>"))
    story.append(Spacer(1, 4 * mm))
    story.append(P(f"<b>{E(L('files'))}:</b> <font name='{mono}'>{E(scan['id'])}/</font>", small))
    story.append(P(f"ECHO Advanced Scan Suite rev {E(model['generator']['version'])} · "
                   f"schema {E(model['schema'])}/{E(model['schema_version'])}", small))

    doc = SimpleDocTemplate(str(out_path), pagesize=A4, leftMargin=margin, rightMargin=margin,
                            topMargin=16 * mm, bottomMargin=16 * mm, title=rep["title"],
                            author=rep["author"] or "ECHO Advanced Scan Suite",
                            subject=f"{scan['target']} - {scan['id']}", creator="ECHO Advanced Scan Suite")
    doc.build(story, onFirstPage=on_page, onLaterPages=on_page)


# --------------------------------------------------------------------------- #
def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="ECHO report generator (PDF/JSON, en/pt-BR)")
    ap.add_argument("--scan-dir", required=True)
    ap.add_argument("--out-dir")
    ap.add_argument("--lang", default="pt-BR", choices=["en", "pt-BR", "both"])
    ap.add_argument("--format", default="both", choices=["pdf", "json", "both"])
    ap.add_argument("--title")
    ap.add_argument("--client")
    ap.add_argument("--author")
    ap.add_argument("--logo")
    a = ap.parse_args(argv)

    scan = Path(a.scan_dir)
    if not (scan / "status.json").exists():
        print(f"[✖] status.json não encontrado em {scan}", file=sys.stderr)
        return 2
    out = Path(a.out_dir) if a.out_dir else scan / "report"
    out.mkdir(parents=True, exist_ok=True)
    langs = ["en", "pt-BR"] if a.lang == "both" else [a.lang]
    rc = 0
    for lang in langs:
        model = build_model(scan, lang, a.title, a.client, a.author)
        if a.format in ("json", "both"):
            p = out / f"report-{lang}.json"
            p.write_text(json.dumps(model, ensure_ascii=False, indent=2))
            print(f"[✔] JSON: {p}")
        if a.format in ("pdf", "both"):
            p = out / f"report-{lang}.pdf"
            try:
                render_pdf(model, p, a.logo)
                print(f"[✔] PDF:  {p}")
            except ImportError:
                print("[!] reportlab não instalado: PDF não gerado (apt install python3-reportlab "
                      "ou pip install reportlab)", file=sys.stderr)
                rc = 1
    return rc


if __name__ == "__main__":
    sys.exit(main())

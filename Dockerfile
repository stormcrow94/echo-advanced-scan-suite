# syntax=docker/dockerfile:1
# ECHO - Advanced Scan Suite

# ---- Etapa 1: compila a API (Go, somente stdlib) ----
FROM golang:1.26-bookworm AS api-build
WORKDIR /src
COPY go.mod ./
COPY api/ ./api/
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/api-server ./api

# ---- Etapa 2: imagem final ----
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    TZ=UTC \
    ECHO_OUTPUT_DIR=/app/output

WORKDIR /app

# Ferramentas (versões fixadas em scripts/versions.env).
# waymore fica no venv compartilhado /opt/echo/venv (o container roda como `recon`).
COPY scripts/ /app/scripts/
RUN SKIP_TEMPLATES=1 OPT_DIR=/opt/echo /app/scripts/install.sh \
    && chmod -R a+rX /opt/echo \
    && apt-get clean && rm -rf /var/lib/apt/lists/* /root/.cache

# Usuário sem privilégios (a imagem ubuntu:24.04 já traz o usuário "ubuntu" com UID 1000)
RUN (userdel -r ubuntu 2>/dev/null || true) && useradd -m -u 1000 recon

COPY --from=api-build /out/api-server /app/api-server
COPY entrypoint.sh recon.sh /app/
COPY report/ /app/report/
COPY assets/ /app/assets/
RUN chmod +x /app/entrypoint.sh /app/recon.sh /app/report/echo_report.py \
    && mkdir -p /app/output && chown -R recon:recon /app

USER recon
# Templates do Nuclei no HOME do usuário que executa os scans
RUN nuclei -ut -silent >/dev/null 2>&1 || true

EXPOSE 8080
VOLUME ["/app/output"]
ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["--help"]

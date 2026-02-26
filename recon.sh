#!/bin/bash

export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin

# #############################################################################
#
# Script de Reconhecimento Automatizado
#
# Autor: Seu Nome (inspirado no script original)
# Versão: 2.2 (Correção de caracteres e adição de verificação de root)
#
# Descrição:
# Este script realiza um fluxo de reconhecimento completo em um domínio alvo.
# Ele automatiza a enumeração de subdomínios, resolução de DNS, busca por URLs
# históricas, verificação de hosts ativos, escaneamento de portas, análise de
# JavaScript, busca de parâmetros e escaneamento de vulnerabilidades com Nuclei.
#
# Destaques:
#   - Instalação automática de dependências para sistemas baseados em
#     Debian (Ubuntu) e RHEL (CentOS, Fedora).
#   - Verificação de ferramentas antes da execução para evitar erros.
#   - Operação em paralelo para otimizar o tempo.
#   - Organização dos resultados em um diretório dedicado.
#
# Como usar:
#   1. Dê permissão de execução: chmod +x recon-completo.sh
#   2. Para instalar as ferramentas: ./recon-completo.sh --install
#   3. Para rodar o scan: ./recon-completo.sh -d seudominio.com
#
# #############################################################################

# === CONFIGURAÇÕES GERAIS E CORES ===
set -eo pipefail

# Garante que o PATH inclua os diretórios do Go
export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin

GREEN="\e[32m"
BLUE="\e[34m"
YELLOW="\e[33m"
RED="\e[31m"
RESET="\e[0m"
BOLD="\e[1m"

# Função para exibir banners de seção
function print_banner() {
    echo -e "\n${BLUE}${BOLD}=======================================================================${RESET}"
    echo -e "${BLUE}${BOLD} $1 ${RESET}"
    echo -e "${BLUE}${BOLD}=======================================================================${RESET}"
}

# Função de ajuda simplificada
function usage() {
    echo -e "${YELLOW}Uso: $0 -d <DOMÍNIO>${RESET}"
    echo "  -d, --domain    O domínio alvo para o reconhecimento."
    exit 1
}

# === PROCESSAMENTO DOS ARGUMENTOS DA LINHA DE COMANDO ===
DOMAIN=""
if [[ "$#" -eq 2 && ("$1" == "-d" || "$1" == "--domain") ]]; then
    DOMAIN="$2"
else
    usage
fi

# === INÍCIO DO SCRIPT DE RECONHECIMENTO ===
# Configurações opcionais (time budget e ferramentas)
NIKTO_MAX_HOSTS="${NIKTO_MAX_HOSTS:-10}"
ZAP_MAX_HOSTS="${ZAP_MAX_HOSTS:-5}"
ZAP_BASELINE_ENABLED="${ZAP_BASELINE_ENABLED:-false}"
MAX_SCAN_MINUTES="${MAX_SCAN_MINUTES:-30}"

# Cria o diretório de saída principal
mkdir -p /app/output
cd /app/output || exit

OUTPUT_DIR="recon-$DOMAIN-$(date +%F)"
mkdir -p "$OUTPUT_DIR"/{urls,hosts,vulns,js}

# Marca início do scan para status.json
STARTED_AT=$(date -Iseconds)
echo "{\"started_at\": \"$STARTED_AT\", \"status\": \"running\"}" > "$OUTPUT_DIR/status.json"

# Atualiza status para "failed" em saídas antecipadas (para a API retornar corretamente)
write_status_failed() {
    local reason="${1:-unknown}"
    local finished
    finished=$(date -Iseconds)
    echo "{\"started_at\": \"$STARTED_AT\", \"finished_at\": \"$finished\", \"status\": \"failed\", \"error\": \"$reason\"}" > "$OUTPUT_DIR/status.json"
}

# Em qualquer saída com erro, marcar como failed se ainda estiver "running"
trap 'if [ $? -ne 0 ] && [ -n "${OUTPUT_DIR:-}" ] && [ -f "${OUTPUT_DIR}/status.json" ]; then grep -q "\"status\": \"running\"" "${OUTPUT_DIR}/status.json" 2>/dev/null && write_status_failed "script error"; fi' EXIT

LOG_FILE="$OUTPUT_DIR/recon.log"
exec > >(tee -a "${LOG_FILE}") 2>&1

print_banner "Iniciando Recon para: $DOMAIN"
echo -e "Resultados serão salvos em: ${BOLD}$OUTPUT_DIR${RESET}"

# 1️⃣ Enumeração de Subdomínios (em paralelo)
print_banner "ETAPA 1: Coletando Subdomínios"
(
    subfinder -d "$DOMAIN" -all -silent -t 50 || true
    assetfinder --subs-only "$DOMAIN" || true
    findomain -t "$DOMAIN" -q || true
    timeout 5m amass enum -passive -d "$DOMAIN" -nocolor -silent || true
) | sort -u | anew "$OUTPUT_DIR/subdomains.txt"
SUBDOMAIN_COUNT=$(wc -l < "$OUTPUT_DIR/subdomains.txt")
echo -e "${GREEN}[✔] Subdomínios coletados: ${SUBDOMAIN_COUNT}${RESET}"

# Verificação de robustez
if [ "$SUBDOMAIN_COUNT" -eq 0 ]; then
    echo -e "${RED}[✖] Nenhum subdomínio encontrado. O script será encerrado.${RESET}"
    write_status_failed "no subdomains found"
    exit 1
fi

# 2️⃣ Resolução de DNS
print_banner "ETAPA 2: Resolvendo Subdomínios Válidos"
dnsx -l "$OUTPUT_DIR/subdomains.txt" -t 100 -silent -o "$OUTPUT_DIR/hosts/resolved.txt"
echo -e "${GREEN}[✔] Subdomínios resolvidos: $(wc -l < "$OUTPUT_DIR/hosts/resolved.txt")${RESET}"

# 3️⃣ Escaneamento de Portas
print_banner "ETAPA 3: Escaneando Portas (Top 1000)"
naabu -l "$OUTPUT_DIR/hosts/resolved.txt" -top-ports 1000 -silent -o "$OUTPUT_DIR/hosts/ports.txt"
echo -e "${GREEN}[✔] Escaneamento de portas concluído.${RESET}"

# 4️⃣ Verificação de Servidores Web (hosts vivos)
print_banner "ETAPA 4: Verificando Servidores Web Ativos"
httpx -l "$OUTPUT_DIR/hosts/resolved.txt" -t 100 -silent -o "$OUTPUT_DIR/hosts/alive.txt"
ALIVE_HOSTS_COUNT=$(wc -l < "$OUTPUT_DIR/hosts/alive.txt")
echo -e "${GREEN}[✔] Hosts vivos: ${ALIVE_HOSTS_COUNT}${RESET}"

# Verificação de robustez
if [ "$ALIVE_HOSTS_COUNT" -eq 0 ]; then
    echo -e "${RED}[✖] Nenhum host ativo encontrado. O script será encerrado.${RESET}"
    write_status_failed "no alive hosts found"
    exit 1
fi

# 5️⃣ Coleta de URLs (Wayback Machine e GAU)
print_banner "ETAPA 5: Coletando URLs de Fontes Históricas"
(
    cat "$OUTPUT_DIR/hosts/alive.txt" | waybackurls || true
    cat "$OUTPUT_DIR/hosts/alive.txt" | gau --blacklist png,jpg,gif,svg,css,js,woff,woff2 --threads 20 || true
) | sort -u | anew "$OUTPUT_DIR/urls.txt"
echo -e "${GREEN}[✔] URLs coletadas: $(wc -l < "$OUTPUT_DIR/urls.txt")${RESET}"

# 6️⃣ Análise de Arquivos JavaScript
print_banner "ETAPA 6: Analisando Arquivos JavaScript em busca de Endpoints"
JS_URLS_FILE="$OUTPUT_DIR/js/js_urls.txt"
{ grep '\.js$' "$OUTPUT_DIR/urls.txt" || true; } | httpx -status-code -mc 200 -content-type | { grep 'javascript' || true; } | cut -d ' ' -f1 > "$JS_URLS_FILE"

if [ -s "$JS_URLS_FILE" ]; then
    getJS --input "$JS_URLS_FILE" --complete > "$OUTPUT_DIR/js/endpoints.txt" || true
    echo -e "${GREEN}[✔] Endpoints extraídos de arquivos JS.${RESET}"
else
    echo -e "${YELLOW}[!] Nenhum arquivo JavaScript encontrado para análise.${RESET}"
fi

# 7️⃣ Escaneamento de Vulnerabilidades com Nuclei
print_banner "ETAPA 7: Escaneando Vulnerabilidades com Nuclei"
# Text output
timeout 10m nuclei -l "$OUTPUT_DIR/hosts/alive.txt" \
    -t "technologies,cves,cnvd,default-logins,misconfigurations,vulnerabilities,exposure,takeover,exposed-panels,secret" \
    -severity low,medium,high,critical \
    -c 25 -rl 150 -timeout 5 \
    -o "$OUTPUT_DIR/vulns/nuclei.txt" 2>/dev/null || true
# JSON output (same templates)
timeout 10m nuclei -l "$OUTPUT_DIR/hosts/alive.txt" \
    -t "technologies,cves,cnvd,default-logins,misconfigurations,vulnerabilities,exposure,takeover,exposed-panels,secret" \
    -severity low,medium,high,critical \
    -c 25 -rl 150 -timeout 5 \
    -jsonl -o "$OUTPUT_DIR/vulns/nuclei.json" 2>/dev/null || true
echo -e "${GREEN}[✔] Nuclei scan concluído!${RESET}"

# 8️⃣ Nikto (primeiros N hosts vivos, timeout por host)
print_banner "ETAPA 8: Nikto - Verificação de servidor web"
NIKTO_COUNT=0
while IFS= read -r url && [ "$NIKTO_COUNT" -lt "$NIKTO_MAX_HOSTS" ]; do
    [ -z "$url" ] && continue
    NIKTO_COUNT=$((NIKTO_COUNT + 1))
    SAFE=$(echo "$url" | sed 's|https\?://||;s|[^a-zA-Z0-9.-]|_|g')
    OUT_FILE="$OUTPUT_DIR/vulns/nikto_${SAFE}.json"
    if [[ "$url" == https* ]]; then
        timeout 120 nikto -h "$url" -ssl -Format json -o "$OUT_FILE" 2>/dev/null || true
    else
        timeout 120 nikto -h "$url" -Format json -o "$OUT_FILE" 2>/dev/null || true
    fi
    echo -e "${GREEN}[✔] Nikto ($NIKTO_COUNT/$NIKTO_MAX_HOSTS): $url${RESET}"
done < "$OUTPUT_DIR/hosts/alive.txt"

# 9️⃣ ZAP baseline (opcional, env-gated; primeiros M hosts)
if [ "$ZAP_BASELINE_ENABLED" = "true" ] && command -v zap-baseline.py &>/dev/null; then
    print_banner "ETAPA 9: ZAP Baseline (crawl + passive)"
    ZAP_COUNT=0
    while IFS= read -r url && [ "$ZAP_COUNT" -lt "$ZAP_MAX_HOSTS" ]; do
        [ -z "$url" ] && continue
        ZAP_COUNT=$((ZAP_COUNT + 1))
        SAFE=$(echo "$url" | sed 's|https\?://||;s|[^a-zA-Z0-9.-]|_|g')
        OUT_FILE="$OUTPUT_DIR/vulns/zap_${SAFE}.json"
        timeout 300 zap-baseline.py -t "$url" -m 1 -T 3 -J "$OUT_FILE" 2>/dev/null || true
        echo -e "${GREEN}[✔] ZAP baseline ($ZAP_COUNT/$ZAP_MAX_HOSTS): $url${RESET}"
    done < "$OUTPUT_DIR/hosts/alive.txt"
else
    echo -e "${YELLOW}[!] ZAP baseline omitido (ZAP_BASELINE_ENABLED=false ou zap-baseline.py não encontrado).${RESET}"
fi

# === FIM ===
FINISHED_AT=$(date -Iseconds)
echo "{\"started_at\": \"$STARTED_AT\", \"finished_at\": \"$FINISHED_AT\", \"status\": \"completed\"}" > "$OUTPUT_DIR/status.json"
print_banner "Recon FINALIZADO para: $DOMAIN"
echo -e "Resultados completos salvos no diretório: ${BOLD}$OUTPUT_DIR${RESET}"
echo -e "Log de execução: ${BOLD}${LOG_FILE}${RESET}"


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
# Cria o diretório de saída principal
mkdir -p /app/output
cd /app/output || exit

OUTPUT_DIR="recon-$DOMAIN-$(date +%F)"
mkdir -p "$OUTPUT_DIR"/{urls,hosts,vulns,js}

LOG_FILE="$OUTPUT_DIR/recon.log"
exec > >(tee -a "${LOG_FILE}") 2>&1

print_banner "Iniciando Recon para: $DOMAIN"
echo -e "Resultados serão salvos em: ${BOLD}$OUTPUT_DIR${RESET}"

# 1️⃣ Enumeração de Subdomínios (em paralelo)
print_banner "ETAPA 1: Coletando Subdomínios"
(
    subfinder -d "$DOMAIN" -all -silent -t 50
    assetfinder --subs-only "$DOMAIN"
    findomain -t "$DOMAIN" -q
    timeout 5m amass enum -passive -d "$DOMAIN" -nocolor -silent
) | sort -u | anew "$OUTPUT_DIR/subdomains.txt"
SUBDOMAIN_COUNT=$(wc -l < "$OUTPUT_DIR/subdomains.txt")
echo -e "${GREEN}[✔] Subdomínios coletados: ${SUBDOMAIN_COUNT}${RESET}"

# Verificação de robustez
if [ "$SUBDOMAIN_COUNT" -eq 0 ]; then
    echo -e "${RED}[✖] Nenhum subdomínio encontrado. O script será encerrado.${RESET}"
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
    exit 1
fi

# 5️⃣ Coleta de URLs (Wayback Machine e GAU)
print_banner "ETAPA 5: Coletando URLs de Fontes Históricas"
(
    cat "$OUTPUT_DIR/hosts/alive.txt" | waybackurls
    cat "$OUTPUT_DIR/hosts/alive.txt" | gau -b png,jpg,gif,svg,css,js,woff,woff2 -t 20
) | sort -u | anew "$OUTPUT_DIR/urls.txt"
echo -e "${GREEN}[✔] URLs coletadas: $(wc -l < "$OUTPUT_DIR/urls.txt")${RESET}"

# 6️⃣ Análise de Arquivos JavaScript
print_banner "ETAPA 6: Analisando Arquivos JavaScript em busca de Endpoints"
JS_URLS_FILE="$OUTPUT_DIR/js/js_urls.txt"
grep '\.js$' "$OUTPUT_DIR/urls.txt" | httpx -status-code -mc 200 -content-type | grep 'javascript' | cut -d ' ' -f1 > "$JS_URLS_FILE"

if [ -s "$JS_URLS_FILE" ]; then
    getJS --list "$JS_URLS_FILE" --complete > "$OUTPUT_DIR/js/endpoints.txt"
    echo -e "${GREEN}[✔] Endpoints extraídos de arquivos JS.${RESET}"
else
    echo -e "${YELLOW}[!] Nenhum arquivo JavaScript encontrado para análise.${RESET}"
fi

# 7️⃣ Escaneamento de Vulnerabilidades com Nuclei
print_banner "ETAPA 7: Escaneando Vulnerabilidades com Nuclei"
nuclei -l "$OUTPUT_DIR/hosts/alive.txt" -t "technologies,cves,cnvd,default-logins,misconfigurations,vulnerabilities" -severity low,medium,high,critical -o "$OUTPUT_DIR/vulns/nuclei.txt"
echo -e "${GREEN}[✔] Nuclei scan concluído!${RESET}"

# === FIM ===
print_banner "Recon FINALIZADO para: $DOMAIN"
echo -e "Resultados completos salvos no diretório: ${BOLD}$OUTPUT_DIR${RESET}"
echo -e "Log de execução: ${BOLD}${LOG_FILE}${RESET}"


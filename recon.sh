#!/usr/bin/env bash
# #############################################################################
#  ECHO - Advanced Scan Suite
#  Reconhecimento automatizado: subdomínios, DNS, portas, web, TLS, URLs,
#  crawling/JS, Nuclei, Nikto (opcional) e relatório PDF/JSON (en / pt-BR).
#
#  Uso rápido:  ./recon.sh -d example.com
#  Ajuda:       ./recon.sh --help
#
#  USE APENAS EM ALVOS QUE VOCÊ POSSUI OU TEM AUTORIZAÇÃO POR ESCRITO PARA TESTAR.
# #############################################################################
set -uo pipefail

ECHO_VERSION="2026.11.2"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Garante que os diretórios usuais de binários Go estejam no PATH
export PATH="${PATH}:/usr/local/go/bin:${HOME}/go/bin:${HOME}/.local/bin:/opt/go/bin"

# === CORES (desligadas se a saída não for um terminal ou NO_COLOR estiver definido) ===
if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
    GREEN=$'\e[32m'; BLUE=$'\e[34m'; CYAN=$'\e[36m'; YELLOW=$'\e[33m'
    RED=$'\e[31m'; BOLD=$'\e[1m'; DIM=$'\e[2m'; RESET=$'\e[0m'
else
    GREEN=""; BLUE=""; CYAN=""; YELLOW=""; RED=""; BOLD=""; DIM=""; RESET=""
fi

info()  { printf '%s[*]%s %s\n' "$BLUE" "$RESET" "$*"; }
ok()    { printf '%s[✔]%s %s\n' "$GREEN" "$RESET" "$*"; }
warn()  { printf '%s[!]%s %s\n' "$YELLOW" "$RESET" "$*"; }
err()   { printf '%s[✖]%s %s\n' "$RED" "$RESET" "$*" >&2; }
die()   { err "$*"; exit 1; }

section() {
    local title="━━━ $1 " line="━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    local pad=$(( 72 - ${#title} )); (( pad < 3 )) && pad=3
    printf '\n%s%s%s%s%s\n' "$CYAN" "$BOLD" "$title" "${line:0:pad}" "$RESET"
}

show_banner() {
    [[ "${NO_BANNER}" == "true" ]] && return 0
    printf '%s%s' "$CYAN" "$BOLD"
    cat <<'BANNER'
  ███████╗ ██████╗██╗  ██╗ ██████╗
  ██╔════╝██╔════╝██║  ██║██╔═══██╗
  █████╗  ██║     ███████║██║   ██║
  ██╔══╝  ██║     ██╔══██║██║   ██║
  ███████╗╚██████╗██║  ██║╚██████╔╝
  ╚══════╝ ╚═════╝╚═╝  ╚═╝ ╚═════╝
BANNER
    printf '%s' "$RESET"
    printf '  %sAdvanced Scan Suite%s  %s·  rev %s  ·  recon · web · vulns · report%s\n' "$BOLD" "$RESET" "$DIM" "$ECHO_VERSION" "$RESET"
    printf '  %sUse somente em alvos autorizados / authorized targets only%s\n\n' "$YELLOW" "$RESET"
}

usage() {
    cat <<USAGE
ECHO - Advanced Scan Suite (rev ${ECHO_VERSION})

Uso: $(basename "$0") -d <DOMÍNIO> [opções]

Alvo e execução:
  -d, --domain DOMÍNIO       Domínio alvo (obrigatório para scan)
  -o, --output DIR           Diretório raiz de saída (padrão: \$ECHO_OUTPUT_DIR ou ./output)
  -p, --profile PERFIL       passive | standard | deep   (padrão: standard)
  -m, --modules LISTA        Lista de módulos (substitui o perfil). Ex: subdomains,dns,web
      --skip LISTA           Módulos a pular. Ex: --skip ports,nuclei
      --rate N               Limite global de requisições/s ao alvo (padrão: 50)
      --top-ports N          Portas do naabu: 100 ou 1000 (padrão: perfil)
      --max-minutes N        Orçamento de tempo total; módulos restantes são pulados (padrão: 60)
      --zap                  Habilita ZAP baseline (somente perfil deep, requer zap-baseline.py)
      --dry-run              Mostra o plano de execução sem enviar tráfego
      --check-deps           Verifica as ferramentas instaladas e sai
      --install              Instala as dependências localmente (scripts/install.sh)
      --no-banner            Não exibe o banner ASCII

Relatório:
      --report-lang LANG     en | pt-BR | both  (padrão: pt-BR)
      --format FMT           pdf | json | both | none  (padrão: both)
      --report-dir DIR       Onde gravar os relatórios (padrão: <scan>/report)
      --report-title TEXTO   Título personalizado
      --client NOME          Nome do cliente / organização
      --author NOME          Autor / analista responsável
      --logo ARQUIVO         Logo PNG/JPG para a capa

Outros:
  -h, --help                 Esta ajuda
  -V, --version              Versão

Módulos: ${ALL_MODULES[*]}
Perfis:
  passive   subdomains, dns, urls (fontes de terceiros + DNS; não toca HTTP do alvo)
  standard  + ports (top 100), web, tls, crawl, js, nuclei (templates não intrusivos)
  deep      + ports (top 1000), nuclei recommended (sem dos/fuzz/brute), nikto, zap*

Exemplos:
  $(basename "$0") -d example.com
  $(basename "$0") -d example.com -p passive --format json
  $(basename "$0") -d example.com --report-lang en --client "ACME" --author "Blue Team"
USAGE
}

# === MÓDULOS E PERFIS ===
ALL_MODULES=(subdomains dns ports web tls urls crawl js nuclei nikto zap)
# shellcheck disable=SC2034  # lidas via expansão indireta ${!profile_var}
PROFILE_passive="subdomains dns urls"
# shellcheck disable=SC2034
PROFILE_standard="subdomains dns ports web tls urls crawl js nuclei"
# shellcheck disable=SC2034
PROFILE_deep="subdomains dns ports web tls urls crawl js nuclei nikto zap"

# === DEFAULTS (podem vir do ambiente) ===
DOMAIN=""
OUTPUT_ROOT="${ECHO_OUTPUT_DIR:-${OUTPUT_DIR:-}}"
PROFILE="${ECHO_PROFILE:-standard}"
MODULES_OVERRIDE=""
SKIP_MODULES=""
RATE="${ECHO_RATE:-50}"
TOP_PORTS="${ECHO_TOP_PORTS:-}"
MAX_SCAN_MINUTES="${MAX_SCAN_MINUTES:-60}"
NIKTO_MAX_HOSTS="${NIKTO_MAX_HOSTS:-5}"
ZAP_MAX_HOSTS="${ZAP_MAX_HOSTS:-3}"
ZAP_BASELINE_ENABLED="${ZAP_BASELINE_ENABLED:-false}"
URLS_MAX="${URLS_MAX:-20000}"
PORTS_ALLOPEN_PCT="${PORTS_ALLOPEN_PCT:-80}"
JS_MAX="${JS_MAX:-150}"
NUCLEI_TIMEOUT_MIN="${NUCLEI_TIMEOUT_MIN:-20}"
REPORT_LANG="${REPORT_LANG:-pt-BR}"
REPORT_FORMAT="${REPORT_FORMAT:-both}"
REPORT_DIR=""
REPORT_TITLE="${REPORT_TITLE:-}"
REPORT_CLIENT="${REPORT_CLIENT:-}"
REPORT_AUTHOR="${REPORT_AUTHOR:-}"
REPORT_LOGO="${REPORT_LOGO:-}"
SCAN_ID=""
DRY_RUN=false
FAKE_IP_NET=false
NO_BANNER="${NO_BANNER:-false}"
ACTION="scan"

need_arg() { [[ -n "${2:-}" && "${2:0:1}" != "-" ]] || die "Opção $1 requer um valor."; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        -d|--domain)      need_arg "$1" "${2:-}"; DOMAIN="$2"; shift 2 ;;
        -o|--output)      need_arg "$1" "${2:-}"; OUTPUT_ROOT="$2"; shift 2 ;;
        -p|--profile)     need_arg "$1" "${2:-}"; PROFILE="$2"; shift 2 ;;
        -m|--modules)     need_arg "$1" "${2:-}"; MODULES_OVERRIDE="$2"; shift 2 ;;
        --skip)           need_arg "$1" "${2:-}"; SKIP_MODULES="$2"; shift 2 ;;
        --rate)           need_arg "$1" "${2:-}"; RATE="$2"; shift 2 ;;
        --top-ports)      need_arg "$1" "${2:-}"; TOP_PORTS="$2"; shift 2 ;;
        --max-minutes)    need_arg "$1" "${2:-}"; MAX_SCAN_MINUTES="$2"; shift 2 ;;
        --zap)            ZAP_BASELINE_ENABLED=true; shift ;;
        --dry-run)        DRY_RUN=true; shift ;;
        --check-deps)     ACTION="check"; shift ;;
        --install)        ACTION="install"; shift ;;
        --no-banner)      NO_BANNER=true; shift ;;
        --report-lang)    need_arg "$1" "${2:-}"; REPORT_LANG="$2"; shift 2 ;;
        --format)         need_arg "$1" "${2:-}"; REPORT_FORMAT="$2"; shift 2 ;;
        --report-dir)     need_arg "$1" "${2:-}"; REPORT_DIR="$2"; shift 2 ;;
        --report-title)   need_arg "$1" "${2:-}"; REPORT_TITLE="$2"; shift 2 ;;
        --client)         need_arg "$1" "${2:-}"; REPORT_CLIENT="$2"; shift 2 ;;
        --author)         need_arg "$1" "${2:-}"; REPORT_AUTHOR="$2"; shift 2 ;;
        --logo)           need_arg "$1" "${2:-}"; REPORT_LOGO="$2"; shift 2 ;;
        --scan-id)        need_arg "$1" "${2:-}"; SCAN_ID="$2"; shift 2 ;;
        -h|--help)        usage; exit 0 ;;
        -V|--version)     echo "ECHO Advanced Scan Suite rev ${ECHO_VERSION}"; exit 0 ;;
        *)                err "Opção desconhecida: $1"; usage; exit 2 ;;
    esac
done

# Padrão do diretório de saída: /app/output dentro do container, ./output fora
if [[ -z "$OUTPUT_ROOT" ]]; then
    if [[ -d /app && -w /app ]]; then OUTPUT_ROOT="/app/output"; else OUTPUT_ROOT="$(pwd)/output"; fi
fi

# === DEPENDÊNCIAS ===
# ferramenta -> módulos que dependem dela
declare -A TOOL_FOR=(
    [subfinder]="subdomains" [findomain]="subdomains" [dnsx]="dns" [naabu]="ports"
    [httpx]="web js" [tlsx]="tls" [waymore]="urls" [katana]="crawl js" [nuclei]="nuclei"
    [nikto]="nikto" [jq]="core" [curl]="core" [python3]="report"
)

# O binário "httpx" pode ser o cliente Python homônimo (pip install httpx).
is_pd_httpx() { command -v httpx >/dev/null 2>&1 && httpx -version 2>&1 | grep -qi 'current version'; }

tool_ok() {
    local t="$1"
    case "$t" in
        httpx) is_pd_httpx ;;
        python3) command -v python3 >/dev/null 2>&1 && python3 -c 'import reportlab' >/dev/null 2>&1 ;;
        *) command -v "$t" >/dev/null 2>&1 ;;
    esac
}

check_deps() {
    local missing=0 t
    section "Verificação de dependências"
    for t in jq curl python3 subfinder findomain dnsx naabu httpx tlsx waymore katana nuclei nikto; do
        if tool_ok "$t"; then
            ok "$(printf '%-10s' "$t") -> $(command -v "$t")"
        else
            missing=$((missing + 1))
            case "$t" in
                httpx)   warn "$(printf '%-10s' "$t") ausente ou é o 'httpx' do Python (precisa do projectdiscovery/httpx) [módulos: ${TOOL_FOR[$t]}]" ;;
                python3) warn "$(printf '%-10s' "$t") python3 + reportlab ausentes (apt install python3-reportlab) [módulos: report PDF]" ;;
                *)       warn "$(printf '%-10s' "$t") não encontrado [módulos: ${TOOL_FOR[$t]}]" ;;
            esac
        fi
    done
    if command -v zap-baseline.py >/dev/null 2>&1; then ok "zap-baseline.py (opcional)"; else info "zap-baseline.py (opcional) não encontrado"; fi
    if [[ -d "${HOME}/nuclei-templates" ]]; then ok "nuclei-templates em ${HOME}/nuclei-templates"; else warn "nuclei-templates ausentes (nuclei -ut)"; fi
    return "$missing"
}

if [[ "$ACTION" == "install" ]]; then
    exec bash "${SCRIPT_DIR}/scripts/install.sh"
fi
if [[ "$ACTION" == "check" ]]; then
    show_banner
    check_deps; m=$?
    if [[ $m -eq 0 ]]; then ok "Todas as ferramentas encontradas."; else warn "$m ferramenta(s) ausente(s): os módulos correspondentes serão pulados."; fi
    exit 0
fi

# === VALIDAÇÕES ===
[[ -n "$DOMAIN" ]] || { usage; exit 2; }
DOMAIN="${DOMAIN,,}"
DOMAIN="${DOMAIN#http://}"; DOMAIN="${DOMAIN#https://}"; DOMAIN="${DOMAIN%%/*}"
DOMAIN_RE='^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$'
[[ ${#DOMAIN} -le 253 && "$DOMAIN" =~ $DOMAIN_RE ]] || die "Domínio inválido: '$DOMAIN'"
[[ "$RATE" =~ ^[0-9]+$ && "$RATE" -ge 1 ]] || die "--rate deve ser inteiro >= 1"
[[ "$MAX_SCAN_MINUTES" =~ ^[0-9]+$ ]] || die "--max-minutes deve ser inteiro"
case "$PROFILE" in passive|standard|deep) ;; *) die "Perfil inválido: $PROFILE (passive|standard|deep)";; esac
case "$REPORT_LANG" in en|pt-BR|both) ;; pt|pt-br|ptbr) REPORT_LANG="pt-BR" ;; *) die "--report-lang inválido: $REPORT_LANG (en|pt-BR|both)";; esac
case "$REPORT_FORMAT" in pdf|json|both|none) ;; *) die "--format inválido: $REPORT_FORMAT (pdf|json|both|none)";; esac
if [[ -z "$TOP_PORTS" ]]; then [[ "$PROFILE" == "deep" ]] && TOP_PORTS=1000 || TOP_PORTS=100; fi
case "$TOP_PORTS" in 100|1000) ;; *) die "--top-ports deve ser 100 ou 1000";; esac
[[ -z "$REPORT_LOGO" || -f "$REPORT_LOGO" ]] || die "Logo não encontrado: $REPORT_LOGO"
if [[ -n "$SCAN_ID" ]]; then
    [[ "$SCAN_ID" =~ ^recon-[a-z0-9.-]+-[0-9]{4}-[0-9]{2}-[0-9]{2}(-[0-9]{6})?(-n[0-9]+)?$ ]] || die "--scan-id inválido"
fi

# Resolve a lista de módulos
profile_var="PROFILE_${PROFILE}"
if [[ -n "$MODULES_OVERRIDE" ]]; then
    read -r -a MODULES <<< "${MODULES_OVERRIDE//,/ }"
else
    read -r -a MODULES <<< "${!profile_var}"
fi
for m in "${MODULES[@]}"; do
    [[ " ${ALL_MODULES[*]} " == *" $m "* ]] || die "Módulo desconhecido: $m"
done
declare -A ENABLED=()
for m in "${MODULES[@]}"; do ENABLED[$m]=1; done
for m in ${SKIP_MODULES//,/ }; do unset "ENABLED[$m]"; done
[[ "$ZAP_BASELINE_ENABLED" == "true" ]] || unset "ENABLED[zap]"
enabled() { [[ -n "${ENABLED[$1]:-}" ]]; }

show_banner

if [[ "$DRY_RUN" == "true" ]]; then
    section "Plano (dry-run)"
    echo "  Alvo:       $DOMAIN"
    echo "  Perfil:     $PROFILE   | rate: ${RATE} req/s | top-ports: ${TOP_PORTS} | orçamento: ${MAX_SCAN_MINUTES} min"
    printf '  Módulos:   '; for m in "${ALL_MODULES[@]}"; do enabled "$m" && printf ' %s' "$m"; done; echo
    echo "  Saída:      ${OUTPUT_ROOT}/recon-${DOMAIN}-<data>-<hora>/"
    echo "  Relatório:  formato=${REPORT_FORMAT} idioma=${REPORT_LANG}"
    check_deps || true
    exit 0
fi

# === DIRETÓRIOS E STATUS ===
mkdir -p "$OUTPUT_ROOT" || die "Não foi possível criar $OUTPUT_ROOT"
[[ -n "$SCAN_ID" ]] || SCAN_ID="recon-${DOMAIN}-$(date +%F-%H%M%S)"
OUT="${OUTPUT_ROOT}/${SCAN_ID}"
mkdir -p "$OUT"/{subdomains,hosts,urls,js,tls,vulns} || die "Não foi possível criar $OUT"
[[ -n "$REPORT_DIR" ]] || REPORT_DIR="${OUT}/report"
LOG_FILE="${OUT}/recon.log"
STATUS_FILE="${OUT}/status.json"
MODSTATE_FILE="${OUT}/.modules.tsv"
: > "$MODSTATE_FILE"
STARTED_AT="$(date -Iseconds)"
START_EPOCH=$(date +%s)
CURRENT_STATUS="running"
ERROR_REASON=""

write_status() {
    local finished="${1:-}"
    local mods="[]"
    if [[ -s "$MODSTATE_FILE" ]]; then
        mods=$(jq -R -s 'split("\n") | map(select(length>0) | split("\t") |
              {name: .[0], status: .[1], seconds: (.[2]|tonumber), detail: .[3]})' "$MODSTATE_FILE")
    fi
    jq -n --arg id "$SCAN_ID" --arg domain "$DOMAIN" --arg profile "$PROFILE" \
          --arg started "$STARTED_AT" --arg finished "$finished" --arg status "$CURRENT_STATUS" \
          --arg error "$ERROR_REASON" --arg version "$ECHO_VERSION" --argjson modules "$mods" \
          --argjson rate "$RATE" --argjson top "$TOP_PORTS" \
        '{id:$id, domain:$domain, profile:$profile, version:$version, rate_limit:$rate, top_ports:$top,
          started_at:$started, status:$status, modules:$modules}
         + (if $finished != "" then {finished_at:$finished} else {} end)
         + (if $error != "" then {error:$error} else {} end)' > "${STATUS_FILE}.tmp" && mv "${STATUS_FILE}.tmp" "$STATUS_FILE"
}

on_exit() {
    local rc=$?
    if [[ "$CURRENT_STATUS" == "running" ]]; then
        CURRENT_STATUS="failed"; ERROR_REASON="${ERROR_REASON:-interrupted or script error (rc=$rc)}"
        write_status "$(date -Iseconds)"
    fi
}
trap on_exit EXIT
trap 'ERROR_REASON="interrupted"; exit 130' INT TERM

write_status
exec > >(tee -a "$LOG_FILE") 2>&1

info "Alvo: ${BOLD}${DOMAIN}${RESET}  | perfil: ${PROFILE} | rate: ${RATE} req/s | scan: ${SCAN_ID}"
info "Resultados: ${OUT}"

# Registra o resultado de um módulo: nome status segundos detalhe
MOD_T0=0
mod_begin() { MOD_T0=$(date +%s); section "$1"; }
mod_end() {
    local name="$1" status="$2" detail="${3:-}"
    printf '%s\t%s\t%s\t%s\n' "$name" "$status" "$(( $(date +%s) - MOD_T0 ))" "${detail//$'\t'/ }" >> "$MODSTATE_FILE"
    write_status
    case "$status" in
        ok) ok "$name: $detail" ;;
        empty) warn "$name: $detail" ;;
        skipped) warn "$name pulado: $detail" ;;
        *) err "$name: $detail" ;;
    esac
}
skip_mod() { MOD_T0=$(date +%s); mod_end "$1" skipped "$2"; }

# Resolve via DNS-over-HTTPS (JSON API) - usado quando o DNS local é um proxy fake-IP
DOH_URL="${DOH_URL:-https://cloudflare-dns.com/dns-query}"
doh_resolve() {
    local h a aaaa
    while IFS= read -r h; do
        [[ -z "$h" ]] && continue
        a=$(curl -fsS -m 10 -H 'accept: application/dns-json' "${DOH_URL}?name=${h}&type=A" 2>/dev/null)
        aaaa=$(curl -fsS -m 10 -H 'accept: application/dns-json' "${DOH_URL}?name=${h}&type=AAAA" 2>/dev/null)
        jq -cn --arg host "$h" --argjson a "${a:-{\}}" --argjson q "${aaaa:-{\}}" \
            '{host:$host, resolver:"doh",
              a:[($a.Answer // [])[] | select(.type==1) | .data],
              aaaa:[($q.Answer // [])[] | select(.type==28) | .data],
              cname:[($a.Answer // [])[] | select(.type==5) | .data | rtrimstr(".")]}' 2>/dev/null
        sleep 0.1
    done < "$1"
}

# Erro fatal da ferramenta (flag inválida, falha de runner...) registrado no stderr
tool_fatal() { [[ -s "$1" ]] && grep -qaE '\[FTL\]|FTL\b|flag provided but not defined|invalid value .* for flag' "$1"; }
fatal_msg() { grep -a -m1 -E 'FTL|flag|invalid' "$1" | sed 's/\x1b\[[0-9;]*m//g' | cut -c1-160; }

budget_left() { (( $(date +%s) - START_EPOCH < MAX_SCAN_MINUTES * 60 )); }
count() { [[ -s "$1" ]] && wc -l < "$1" | tr -d ' ' || echo 0; }

# Decide se um módulo roda: habilitado, ferramentas presentes, tempo disponível
should_run() {
    local mod="$1"; shift
    enabled "$mod" || return 1
    local t
    for t in "$@"; do
        if ! tool_ok "$t"; then skip_mod "$mod" "ferramenta ausente: $t"; return 1; fi
    done
    if ! budget_left; then skip_mod "$mod" "orçamento de tempo (${MAX_SCAN_MINUTES} min) esgotado"; return 1; fi
    return 0
}

SUBS="${OUT}/subdomains.txt"; RESOLVED="${OUT}/hosts/resolved.txt"; PORTS="${OUT}/hosts/ports.txt"
ALIVE="${OUT}/hosts/alive.txt"; URLS="${OUT}/urls.txt"; CRAWL="${OUT}/urls/crawl.txt"
touch "$SUBS" "$RESOLVED" "$PORTS" "$ALIVE" "$URLS" "$CRAWL"
in_scope() { grep -aiE "(^|\.)${DOMAIN//./\\.}\$" || true; }

# 1) Subdomínios (fontes passivas)
if enabled subdomains; then
    mod_begin "Subdomínios (passivo)"
    srcs=()
    if tool_ok subfinder; then timeout 5m subfinder -d "$DOMAIN" -all -silent -duc > "$OUT/subdomains/subfinder.txt" 2>>"$OUT/subdomains/errors.log"; srcs+=("subfinder:$(count "$OUT/subdomains/subfinder.txt")"); fi
    if tool_ok findomain; then timeout 5m findomain -t "$DOMAIN" -q > "$OUT/subdomains/findomain.txt" 2>>"$OUT/subdomains/errors.log"; srcs+=("findomain:$(count "$OUT/subdomains/findomain.txt")"); fi
    # crt.sh (Certificate Transparency), com tolerância a instabilidade do serviço
    if curl -fsS --retry 4 --retry-delay 10 --retry-all-errors -m 90 "https://crt.sh/?q=%25.${DOMAIN}&output=json" -o "$OUT/subdomains/crtsh.json" 2>>"$OUT/subdomains/errors.log"; then
        jq -r '.[].name_value' "$OUT/subdomains/crtsh.json" 2>/dev/null | tr '[:upper:]' '[:lower:]' | sed 's/^\*\.//' > "$OUT/subdomains/crtsh.txt"
    fi
    srcs+=("crt.sh:$(count "$OUT/subdomains/crtsh.txt")")
    { echo "$DOMAIN"; cat "$OUT"/subdomains/*.txt 2>/dev/null; } | tr -d '\r' | tr '[:upper:]' '[:lower:]' | sed 's/^\*\.//; s/\.$//' \
        | in_scope | sort -u > "$SUBS"
    mod_end subdomains ok "$(count "$SUBS") subdomínios (${srcs[*]})"
else
    echo "$DOMAIN" > "$SUBS"
fi

# 2) DNS
if should_run dns dnsx; then
    mod_begin "Resolução DNS"
    timeout 10m dnsx -l "$SUBS" -rl "$RATE" -t 25 -silent -duc -a -aaaa -cname -resp -json -o "$OUT/hosts/dns.json" >/dev/null 2>"$OUT/hosts/dnsx.err"
    jq -r 'select((.a // []) + (.aaaa // []) | length > 0) | .host' "$OUT/hosts/dns.json" 2>/dev/null | sort -u > "$RESOLVED"
    n=$(count "$RESOLVED")
    # Redes com proxy transparente "fake-IP" (198.18.0.0/15) devolvem o mesmo IP falso para tudo:
    # varredura de portas e IPs ficam sem sentido nesse ambiente.
    total_a=$(jq -r '.a[]?' "$OUT/hosts/dns.json" 2>/dev/null | wc -l)
    fake_a=$(jq -r '.a[]?' "$OUT/hosts/dns.json" 2>/dev/null | grep -cE '^198\.(18|19)\.' || true)
    if [[ "$total_a" -gt 0 && $(( fake_a * 100 / total_a )) -ge 50 ]]; then
        FAKE_IP_NET=true
        warn "DNS devolveu IPs de 198.18.0.0/15 (proxy fake-IP da sua rede): portas/IPs não serão confiáveis."
        warn "Re-resolvendo via DNS-over-HTTPS (${DOH_URL}) para obter os registros reais."
        mv "$OUT/hosts/dns.json" "$OUT/hosts/dns_local.json"
        doh_resolve "$SUBS" > "$OUT/hosts/dns.json"
        jq -r 'select((.a // []) + (.aaaa // []) | length > 0) | .host' "$OUT/hosts/dns.json" 2>/dev/null | sort -u > "$RESOLVED"
        n=$(count "$RESOLVED")
    fi
    if tool_fatal "$OUT/hosts/dnsx.err"; then mod_end dns failed "$(fatal_msg "$OUT/hosts/dnsx.err")"
    elif [[ "$n" -gt 0 ]]; then mod_end dns ok "$n hosts resolvidos"; else mod_end dns empty "nenhum host resolvido"; fi
else
    [[ -s "$RESOLVED" ]] || cp "$SUBS" "$RESOLVED"
fi

# 3) Portas (connect scan sem root, limitado por rate e excluindo CDN)
if enabled ports && [[ "$FAKE_IP_NET" == "true" && "${ECHO_FORCE_PORTS:-false}" != "true" ]]; then
    skip_mod ports "rede com proxy fake-IP (198.18.0.0/15): resultados seriam falsos; use ECHO_FORCE_PORTS=true para forçar"
elif should_run ports naabu; then
    mod_begin "Portas (top ${TOP_PORTS})"
    if [[ ! -s "$RESOLVED" ]]; then
        mod_end ports empty "sem hosts para escanear"
    else
        scan_type="c"; [[ $EUID -eq 0 ]] && scan_type="s"
        timeout 15m naabu -l "$RESOLVED" -top-ports "$TOP_PORTS" -rate "$RATE" -c 25 -scan-type "$scan_type" \
            -exclude-cdn -silent -duc -o "$PORTS" >/dev/null 2>"$OUT/hosts/naabu.err"
        # Hosts que "respondem" em quase todas as portas (firewall/WAF/tarpit) geram falsos positivos
        # e multiplicam o tráfego das etapas seguintes: mantemos só 80/443 deles e registramos à parte.
        limit=$(( TOP_PORTS * PORTS_ALLOPEN_PCT / 100 ))
        awk -F: '{c[$1]++} END {for (h in c) print h"\t"c[h]}' "$PORTS" | awk -F'\t' -v l="$limit" '$2 >= l {print $1}' \
            | sort > "$OUT/hosts/ports_all_open.txt"
        if [[ -s "$OUT/hosts/ports_all_open.txt" ]]; then
            cp "$PORTS" "$OUT/hosts/ports_raw.txt"
            awk -F: 'NR==FNR {sus[$1]=1; next} !($1 in sus) || $2==80 || $2==443' "$OUT/hosts/ports_all_open.txt" "$OUT/hosts/ports_raw.txt" > "$PORTS"
        fi
        n=$(count "$PORTS"); na=$(count "$OUT/hosts/ports_all_open.txt")
        extra=""; [[ "$na" -gt 0 ]] && extra=", $na host(s) respondem em ≥${PORTS_ALLOPEN_PCT}% das portas (filtrados p/ 80,443)"
        if tool_fatal "$OUT/hosts/naabu.err"; then mod_end ports failed "$(fatal_msg "$OUT/hosts/naabu.err")"
        elif [[ "$n" -gt 0 ]]; then mod_end ports ok "$n host:porta abertos (scan $scan_type$extra)"; else mod_end ports empty "nenhuma porta aberta encontrada"; fi
    fi
fi

# 4) Web (httpx): hosts vivos, títulos, tecnologias
if should_run web httpx; then
    mod_begin "Servidores web (httpx)"
    # hosts resolvidos (httpx testa 80/443) + portas não padrão encontradas pelo naabu
    { cat "$RESOLVED"; awk -F: '$NF!=80 && $NF!=443' "$PORTS"; } | sort -u > "$OUT/hosts/web_targets.txt"
    timeout 15m httpx -l "$OUT/hosts/web_targets.txt" -rl "$RATE" -t 25 -silent -duc -no-color \
        -nf -sc -title -td -server -ip -cdn -location -json -o "$OUT/hosts/httpx.json" >/dev/null 2>"$OUT/hosts/httpx.err"
    jq -r '.url' "$OUT/hosts/httpx.json" 2>/dev/null | sed -E 's#^(http://[^/]+):80(/|$)#\1\2#; s#^(https://[^/]+):443(/|$)#\1\2#' \
        | sort -u > "$ALIVE"
    n=$(count "$ALIVE")
    if tool_fatal "$OUT/hosts/httpx.err"; then mod_end web failed "$(fatal_msg "$OUT/hosts/httpx.err")"
    elif [[ "$n" -gt 0 ]]; then mod_end web ok "$n URLs web ativas"; else mod_end web empty "nenhum servidor web ativo"; fi
fi

# 5) TLS (tlsx): certificados expirados, autoassinados, nome divergente
if should_run tls tlsx; then
    mod_begin "Certificados TLS (tlsx)"
    grep -E '^https://' "$ALIVE" | sed -E 's#^https://##; s#/.*$##' | awk -F: '{print ($2==""? $1":443" : $0)}' | sort -u > "$OUT/tls/targets.txt"
    if [[ -s "$OUT/tls/targets.txt" ]]; then
        timeout 10m tlsx -l "$OUT/tls/targets.txt" -c 10 -silent -duc -json -tv -ex -ss -mm -un -o "$OUT/tls/tlsx.json" >/dev/null 2>"$OUT/tls/tlsx.err"
        if tool_fatal "$OUT/tls/tlsx.err"; then mod_end tls failed "$(fatal_msg "$OUT/tls/tlsx.err")"
        else mod_end tls ok "$(count "$OUT/tls/tlsx.json") certificados analisados"; fi
    else
        mod_end tls empty "nenhum endpoint HTTPS"
    fi
fi

# 6) URLs históricas (waymore: Wayback, Common Crawl, OTX, URLScan, GhostArchive)
# -mode U: só URLs (não baixa respostas arquivadas). Subdomínios vêm no padrão.
# Nenhuma chave de API é exigida. A saída continua em urls.txt para o relatório e o módulo js.
run_waymore() {
    local budget="$1"
    # -ow sobrescreve; -lcc 1 usa só a coleção mais recente do Common Crawl.
    # -wrlr/-urlr limitam a espera em caso de 429 para não consumir todo o timeout.
    timeout "$budget" waymore -i "$DOMAIN" -mode U -oU "$OUT/urls/waymore.txt" -ow \
        -lcc 1 -p 2 -r 1 -wrlr 1 -urlr 1 \
        >/dev/null 2>>"$OUT/urls/errors.log" || true
}

normalize_waymore_urls() {
    : > "$URLS"
    if [[ -s "$OUT/urls/waymore.txt" ]]; then
        local filtered="$OUT/urls/filtered.txt"
        # Remove estáticos comuns (mantém .js — o módulo js lê urls.txt).
        grep -aE '^https?://' "$OUT/urls/waymore.txt" 2>/dev/null \
            | grep -aviE '\.(png|jpe?g|gif|svg|ico|css|woff2?|ttf|eot|mp4|webp)([?#]|$)' \
            | sort -u > "$filtered" || true
        # Ao aplicar o teto, prioriza arquivos .js para não perdê-los no corte alfabético.
        {
            grep -aiE '^https?://[^/]+/[^?#]*\.js([?#].*)?$' "$filtered" || true
            grep -aviE '^https?://[^/]+/[^?#]*\.js([?#].*)?$' "$filtered" || true
        } | awk 'NF && !seen[$0]++' | head -n "$URLS_MAX" > "$URLS" || true
        rm -f "$filtered"
    fi
}

if should_run urls waymore; then
    mod_begin "URLs históricas (waymore)"
    run_waymore 12m
    normalize_waymore_urls
    if [[ ! -s "$URLS" ]]; then  # fontes públicas (Wayback/OTX) oscilam bastante: uma nova tentativa
        warn "waymore não retornou URLs; tentando novamente em 20 s"
        sleep 20
        run_waymore 12m
        normalize_waymore_urls
    fi
    n=$(count "$URLS")
    if [[ "$n" -gt 0 ]]; then mod_end urls ok "$n URLs (limite ${URLS_MAX})"; else mod_end urls empty "nenhuma URL histórica"; fi
fi

# 7) Crawling (katana, com parsing de JavaScript)
if should_run crawl katana; then
    mod_begin "Crawling (katana)"
    if [[ -s "$ALIVE" ]]; then
        timeout 15m katana -list "$ALIVE" -d 3 -jc -kf all -rl "$RATE" -c 5 -p 3 -ct "${CRAWL_DURATION:-5m}" -fs rdn \
            -ef png,jpg,jpeg,gif,svg,ico,css,woff,woff2,ttf,eot -silent -duc -o "$CRAWL" >/dev/null 2>"$OUT/urls/katana.err"
        rc=$?
        touch "$CRAWL"; sort -u -o "$CRAWL" "$CRAWL"
        if [[ $rc -ne 0 && $rc -ne 124 && ! -s "$CRAWL" ]]; then
            mod_end crawl failed "katana rc=$rc: $(head -c 160 "$OUT/urls/katana.err" | tr '\n' ' ')"
        else
            mod_end crawl ok "$(count "$CRAWL") URLs rastreadas"
        fi
    else
        mod_end crawl empty "nenhum host web ativo"
    fi
fi

# 8) JavaScript: arquivos .js ativos + extração de endpoints
if should_run js httpx curl; then
    mod_begin "Análise de JavaScript"
    cat "$CRAWL" "$URLS" 2>/dev/null | grep -aiE '^https?://[^/]+/[^?#]*\.js([?#].*)?$' | awk '!seen[$0]++' | head -n "$((JS_MAX * 4))" > "$OUT/js/js_candidates.txt"
    : > "$OUT/js/js_urls.txt"; : > "$OUT/js/endpoints.txt"
    if [[ -s "$OUT/js/js_candidates.txt" ]]; then
        httpx -l "$OUT/js/js_candidates.txt" -rl "$RATE" -t 10 -silent -duc -no-color -mc 200 -json -o "$OUT/js/httpx_js.json" >/dev/null 2>>"$OUT/js/errors.log"
        jq -r 'select((.content_type // "") | test("javascript|ecmascript|text/plain")) | .url' "$OUT/js/httpx_js.json" 2>/dev/null \
            | sort -u | head -n "$JS_MAX" > "$OUT/js/js_urls.txt"
        while IFS= read -r jsurl; do
            curl -fsSL -m 15 --max-filesize 3000000 -A "Mozilla/5.0 (ECHO-scan)" "$jsurl" 2>/dev/null \
              | grep -aoE "[\"'\`](https?://[A-Za-z0-9._~:/?#@!$&()*+,;=%-]{4,}|/[A-Za-z0-9_][A-Za-z0-9._~/?#@!$&()*+,;=%-]{2,})[\"'\`]" \
              | tr -d "\"'\`" | grep -avE '\.(png|jpe?g|gif|svg|css|woff2?|ttf|ico)(\?|$)' \
              | sed "s#^#${jsurl}\t#"
            sleep "$(awk -v r="$RATE" 'BEGIN{printf "%.3f", 1/r}')"
        done < "$OUT/js/js_urls.txt" | awk -F'\t' '!seen[$2]++' > "$OUT/js/endpoints_by_file.tsv"
        cut -f2 "$OUT/js/endpoints_by_file.tsv" | sort -u > "$OUT/js/endpoints.txt"
    fi
    mod_end js ok "$(count "$OUT/js/js_urls.txt") arquivos JS, $(count "$OUT/js/endpoints.txt") endpoints"
fi

# 9) Nuclei
if should_run nuclei nuclei; then
    mod_begin "Vulnerabilidades (nuclei)"
    if [[ ! -s "$ALIVE" ]]; then
        mod_end nuclei empty "nenhum host web ativo"
    else
        [[ -d "${HOME}/nuclei-templates" ]] || nuclei -ut -silent >/dev/null 2>&1 || true
        NUCLEI_EXCLUDE_TAGS="${NUCLEI_EXCLUDE_TAGS:-dos,fuzz,fuzzing,intrusive,bruteforce,brute-force,default-login,credential-stuffing,token-spray,dast,headless}"
        if [[ "$PROFILE" == "deep" ]]; then
            nuclei_sel=(-profile recommended -severity "${NUCLEI_SEVERITY:-info,low,medium,high,critical}")
        else
            # Tecnologias já vêm do httpx (-td); aqui só o que indica risco (low+), sem interactsh (OAST)
            nuclei_sel=(-t "http/misconfiguration,http/exposures,http/exposed-panels,http/takeovers,ssl,dns"
                        -severity "${NUCLEI_SEVERITY:-low,medium,high,critical}" -ni)
        fi
        # Um alvo por host:porta (prefere HTTPS quando o mesmo host responde nos dois esquemas)
        awk '{u=$0; k=u; sub(/^https?:\/\//,"",k); sub(/\/.*/,"",k); sub(/:(80|443)$/,"",k);
              if (!(k in best) || u ~ /^https:/) best[k]=u} END {for (k in best) print best[k]}' "$ALIVE" \
            | sort > "$OUT/vulns/targets.txt"
        timeout "${NUCLEI_TIMEOUT_MIN}m" nuclei -l "$OUT/vulns/targets.txt" "${nuclei_sel[@]}" -etags "$NUCLEI_EXCLUDE_TAGS" \
            -rl "$RATE" -c 10 -bs 10 -timeout 10 -retries 1 -duc -silent -nc -jsonl -o "$OUT/vulns/nuclei.json" \
            >/dev/null 2>"$OUT/vulns/nuclei.err"
        rc=$?
        jq -r '"[\(.info.severity)] [\(."template-id")] \(."matched-at" // .host) \((."extracted-results" // []) | join(","))"' \
            "$OUT/vulns/nuclei.json" 2>/dev/null > "$OUT/vulns/nuclei.txt"
        n=$(count "$OUT/vulns/nuclei.json")
        if grep -q 'FTL\|Could not run nuclei' "$OUT/vulns/nuclei.err" 2>/dev/null; then
            mod_end nuclei failed "erro do nuclei: $(grep -m1 -E 'FTL|Could not' "$OUT/vulns/nuclei.err" | cut -c1-160)"
        elif [[ $rc -eq 124 ]]; then
            mod_end nuclei ok "$n achados (timeout de ${NUCLEI_TIMEOUT_MIN} min atingido)"
        else
            mod_end nuclei ok "$n achados"
        fi
    fi
fi

# 10) Nikto (perfil deep; primeiros N hosts, tempo limitado, sem testes de DoS)
if should_run nikto nikto; then
    mod_begin "Nikto"
    c=0
    while IFS= read -r url && [[ $c -lt $NIKTO_MAX_HOSTS ]]; do
        [[ -z "$url" ]] && continue
        c=$((c + 1)); safe=$(sed -E 's#^https?://##; s#[^a-zA-Z0-9.-]#_#g' <<< "$url")
        timeout 600 nikto -h "$url" -nointeractive -ask no -maxtime 300s -Tuning x6 -Pause 0.2 \
            -Format json -o "$OUT/vulns/nikto_${safe}.json" >/dev/null 2>>"$OUT/vulns/nikto.err"
        info "Nikto ($c/$NIKTO_MAX_HOSTS): $url"
    done < "$ALIVE"
    mod_end nikto ok "$c host(s) analisados"
fi

# 11) ZAP baseline (opcional)
if enabled zap; then
    if command -v zap-baseline.py >/dev/null 2>&1 && budget_left; then
        mod_begin "ZAP baseline"
        c=0
        while IFS= read -r url && [[ $c -lt $ZAP_MAX_HOSTS ]]; do
            [[ -z "$url" ]] && continue
            c=$((c + 1)); safe=$(sed -E 's#^https?://##; s#[^a-zA-Z0-9.-]#_#g' <<< "$url")
            timeout 600 zap-baseline.py -t "$url" -m 2 -T 8 -J "$OUT/vulns/zap_${safe}.json" >/dev/null 2>>"$OUT/vulns/zap.err" || true
        done < "$ALIVE"
        mod_end zap ok "$c host(s) analisados"
    else
        skip_mod zap "zap-baseline.py ausente ou orçamento esgotado"
    fi
fi

# === RELATÓRIO ===
CURRENT_STATUS="completed"
FINISHED_AT="$(date -Iseconds)"
write_status "$FINISHED_AT"

if [[ "$REPORT_FORMAT" != "none" ]]; then
    section "Relatório"
    if command -v python3 >/dev/null 2>&1; then
        report_args=(--scan-dir "$OUT" --out-dir "$REPORT_DIR" --lang "$REPORT_LANG" --format "$REPORT_FORMAT")
        [[ -n "$REPORT_TITLE"  ]] && report_args+=(--title "$REPORT_TITLE")
        [[ -n "$REPORT_CLIENT" ]] && report_args+=(--client "$REPORT_CLIENT")
        [[ -n "$REPORT_AUTHOR" ]] && report_args+=(--author "$REPORT_AUTHOR")
        [[ -n "$REPORT_LOGO"   ]] && report_args+=(--logo "$REPORT_LOGO")
        if python3 "${SCRIPT_DIR}/report/echo_report.py" "${report_args[@]}"; then
            ok "Relatórios em: ${REPORT_DIR}"
        else
            warn "Falha ao gerar relatório (dados brutos preservados em ${OUT})"
        fi
    else
        warn "python3 ausente: relatório não gerado"
    fi
fi

section "Recon finalizado: $DOMAIN"
printf '  Duração:     %s\n'  "$(( ($(date +%s) - START_EPOCH) / 60 )) min $(( ($(date +%s) - START_EPOCH) % 60 )) s"
printf '  Resultados:  %s\n' "$OUT"
printf '  Log:         %s\n' "$LOG_FILE"

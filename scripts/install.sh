#!/usr/bin/env bash
# ECHO - instalador de dependências (Debian/Ubuntu, RHEL/Fedora/Rocky/Alma, e dentro do Dockerfile).
# Baixa binários oficiais (releases do GitHub) nas versões de scripts/versions.env.
#
#   sudo ./scripts/install.sh              # instala em /usr/local/bin
#   PREFIX=$HOME/.local ./scripts/install.sh   # sem root (pula pacotes do sistema)
#   SKIP_SYSTEM_PACKAGES=1 / SKIP_NIKTO=1 / SKIP_TEMPLATES=1
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/versions.env
source "${HERE}/versions.env"

PREFIX="${PREFIX:-/usr/local}"
BIN="${PREFIX}/bin"
OPT="${OPT_DIR:-${PREFIX}/share/echo}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

log()  { printf '\033[36m[install]\033[0m %s\n' "$*"; }
fail() { printf '\033[31m[install] %s\033[0m\n' "$*" >&2; exit 1; }

case "$(uname -m)" in
    x86_64|amd64) ARCH=amd64 ;;
    aarch64|arm64) ARCH=arm64 ;;
    *) fail "Arquitetura não suportada: $(uname -m)" ;;
esac
[[ "$(uname -s)" == "Linux" ]] || fail "Somente Linux é suportado (use o Docker em outros sistemas)."

SUDO=""
if [[ $EUID -ne 0 ]]; then command -v sudo >/dev/null 2>&1 && SUDO="sudo"; fi

install_system_packages() {
    [[ "${SKIP_SYSTEM_PACKAGES:-0}" == "1" ]] && { log "Pulando pacotes do sistema"; return; }
    if command -v apt-get >/dev/null 2>&1; then
        log "Instalando pacotes (apt)"
        $SUDO env DEBIAN_FRONTEND=noninteractive apt-get update -qq
        $SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
            ca-certificates tzdata curl unzip git jq libpcap0.8 python3 python3-reportlab fonts-dejavu-core \
            perl libnet-ssleay-perl libio-socket-ssl-perl libjson-perl libxml-writer-perl
    elif command -v dnf >/dev/null 2>&1; then
        log "Instalando pacotes (dnf)"
        $SUDO dnf install -y -q epel-release >/dev/null 2>&1 || true
        $SUDO dnf install -y -q ca-certificates tzdata curl unzip git jq libpcap python3 python3-reportlab \
            dejavu-sans-fonts dejavu-sans-mono-fonts perl perl-Net-SSLeay perl-IO-Socket-SSL perl-JSON perl-XML-Writer \
            || log "Alguns pacotes opcionais não estão disponíveis; verifique com ./recon.sh --check-deps"
    else
        log "Gerenciador de pacotes não suportado: instale manualmente curl, unzip, git, jq, libpcap, python3-reportlab"
    fi
    # Fallback do reportlab (PEP 668: nunca usar pip no Python do sistema sem --user/venv)
    if ! python3 -c 'import reportlab' >/dev/null 2>&1; then
        log "python3-reportlab indisponível no gerenciador; tentando pip --user"
        python3 -m pip install --user --quiet reportlab 2>/dev/null \
            || python3 -m pip install --user --quiet --break-system-packages reportlab \
            || log "Não foi possível instalar reportlab: relatórios PDF ficarão desativados (JSON continua)"
    fi
}

gh_zip() {  # owner/repo tag asset binary
    local repo="$1" tag="$2" asset="$3" bin="$4"
    log "  ${bin} ${tag}"
    curl -fsSL --retry 3 -o "${TMP}/${asset}" "https://github.com/${repo}/releases/download/${tag}/${asset}"
    case "$asset" in
        *.zip) unzip -o -q "${TMP}/${asset}" -d "${TMP}/x-${bin}" ;;
        *.tar.gz) mkdir -p "${TMP}/x-${bin}" && tar -xzf "${TMP}/${asset}" -C "${TMP}/x-${bin}" ;;
    esac
    $SUDO install -m 0755 "$(find "${TMP}/x-${bin}" -type f -name "$bin" | head -1)" "${BIN}/${bin}"
}

install_tools() {
    $SUDO mkdir -p "$BIN" "$OPT"
    log "Ferramentas ProjectDiscovery / gau / findomain (${ARCH})"
    local t v
    for t in subfinder dnsx naabu httpx tlsx katana nuclei; do
        v="$(echo "$t" | tr '[:lower:]' '[:upper:]')_VERSION"; v="${!v}"
        gh_zip "projectdiscovery/${t}" "v${v}" "${t}_${v}_linux_${ARCH}.zip" "$t"
    done
    gh_zip lc/gau "v${GAU_VERSION}" "gau_${GAU_VERSION}_linux_${ARCH}.tar.gz" gau
    local fd_asset="findomain-linux.zip"; [[ "$ARCH" == "arm64" ]] && fd_asset="findomain-aarch64.zip"
    gh_zip Findomain/Findomain "${FINDOMAIN_VERSION}" "$fd_asset" findomain

    if [[ "${SKIP_NIKTO:-0}" != "1" ]]; then
        log "  nikto ${NIKTO_VERSION}"
        $SUDO rm -rf "${OPT}/nikto"
        $SUDO git clone -q --depth 1 --branch "${NIKTO_VERSION}" https://github.com/sullo/nikto.git "${OPT}/nikto"
        $SUDO ln -sf "${OPT}/nikto/program/nikto.pl" "${BIN}/nikto"
    fi
}

install_templates() {
    [[ "${SKIP_TEMPLATES:-0}" == "1" ]] && return
    log "Atualizando nuclei-templates (usuário $(id -un))"
    "${BIN}/nuclei" -ut -silent >/dev/null 2>&1 || log "Falha ao baixar templates; o recon.sh tenta de novo na primeira execução"
}

install_system_packages
install_tools
install_templates
log "Concluído. Verifique com: ./recon.sh --check-deps"
case ":$PATH:" in *":${BIN}:"*) ;; *) log "Adicione ${BIN} ao PATH." ;; esac

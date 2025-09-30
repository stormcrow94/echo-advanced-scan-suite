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
# Note: set -e removed to allow scan to continue even if individual tools fail
set -o pipefail

# Garante que o PATH inclua os diretórios do Go para a sessão atual do script
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

# Função de ajuda
function usage() {
    echo -e "${YELLOW}Uso: $0 -d <DOMÍNIO> [OPÇÕES]${RESET}"
    echo "Opções:"
    echo "  -d, --domain    O domínio alvo para o reconhecimento."
    echo "      --install   Instala todas as ferramentas e dependências necessárias."
    echo "  -h, --help      Mostra esta mensagem de ajuda."
    exit 1
}

# === FUNÇÃO DE INSTALAÇÃO DE DEPENDÊNCIAS ===
function install_dependencies() {
    print_banner "Iniciando a Instalação de Dependências"

    # Verifica se o usuário é root
    if [ "$EUID" -eq 0 ]; then
        echo -e "${YELLOW}[!] Aviso: Recomenda-se executar a instalação como um usuário normal com privilégios sudo.${RESET}"
        echo -e "${YELLOW}[!] O Go será instalado no diretório do usuário que executa o script.${RESET}"
    fi

    # Verifica se o Go está instalado
    if ! command -v go &> /dev/null; then
        echo -e "${YELLOW}[!] Go não encontrado. Instalando...${RESET}"
        (
            cd /tmp || exit
            wget -q https://go.dev/dl/go1.22.4.linux-amd64.tar.gz
            sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go1.22.4.linux-amd64.tar.gz
            echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc
        )
        echo -e "${GREEN}[✔] Go instalado com sucesso.${RESET}"
    else
        echo -e "${GREEN}[✔] Go já está instalado.${RESET}"
    fi

    # Detecta o gerenciador de pacotes
    # if command -v apt-get &> /dev/null; then
    #     PKG_MANAGER="sudo apt-get install -y"
    #     ${PKG_MANAGER} git wget curl jq nmap libpcap-dev
    # elif command -v dnf &> /dev/null; then
    #     PKG_MANAGER="sudo dnf install -y"
    #     ${PKG_MANAGER} git wget curl jq nmap libpcap-devel
    # elif command -v yum &> /dev/null; then
    #     PKG_MANAGER="sudo yum install -y"
    #     ${PKG_MANAGER} git wget curl jq nmap libpcap-devel
    # else
    #     echo -e "${RED}[✖] Gerenciador de pacotes não suportado. Instale as ferramentas manualmente.${RESET}"
    #     exit 1
    # fi

    echo -e "${GREEN}[✔] Dependências base (git, wget, curl, jq, nmap) instaladas.${RESET}"

    # Lista de ferramentas para instalar via Go
    tools=(
        "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        "github.com/tomnomnom/assetfinder@latest"
        "github.com/owasp-amass/amass/v4/cmd/amass@master"
        "github.com/tomnomnom/anew@latest"
        "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
        "github.com/tomnomnom/waybackurls@latest"
        "github.com/lc/gau/v2/cmd/gau@latest"
        "github.com/projectdiscovery/httpx/cmd/httpx@latest"
        "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
        "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
        "github.com/003random/getJS@latest"
        "github.com/devanshbatham/paramspider@latest"
    )

    for tool in "${tools[@]}"; do
        tool_name=$(basename "$tool" | cut -d '@' -f 1)
        if ! command -v "$tool_name" &> /dev/null; then
            echo -e "${YELLOW}[!] Instalando $tool_name...${RESET}"
            go install -v "$tool"
        else
            echo -e "${GREEN}[✔] $tool_name já está instalado.${RESET}"
        fi
    done

    # Instala o findomain
    if ! command -v findomain &> /dev/null; then
        echo -e "${YELLOW}[!] Instalando findomain...${RESET}"
        cd /tmp || exit
        wget -q https://github.com/Findomain/Findomain/releases/download/10.0.1/findomain-linux.zip
        unzip findomain-linux.zip
        sudo mv findomain /usr/local/bin/
        rm findomain-linux.zip
        cd -
    else
        echo -e "${GREEN}[✔] findomain já está instalado.${RESET}"
    fi

    # Atualiza os templates do Nuclei
    echo -e "${YELLOW}[!] Atualizando templates do Nuclei...${RESET}"
    nuclei -update-templates

    echo -e "\n${GREEN}${BOLD}Instalação concluída! Por favor, execute 'source ~/.bashrc' ou abra um novo terminal para que o PATH seja atualizado.${RESET}"
    exit 0
}

# === FUNÇÃO PARA VERIFICAR SE AS FERRAMENTAS EXISTEM ===
function check_tools() {
    print_banner "Verificando se as ferramentas necessárias existem"
    local missing_tools=0
    # Ferramentas que serão usadas no scan
    required_tools=(
        "subfinder" "assetfinder" "findomain" "amass" "anew" "dnsx"
        "naabu" "httpx" "waybackurls" "gau" "getJS" "nuclei"
    )

    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            echo -e "${RED}[✖] Ferramenta '${tool}' não encontrada.${RESET}"
            missing_tools=1
        fi
    done

    if [ ${missing_tools} -eq 1 ]; then
        echo -e "\n${YELLOW}[!] Uma ou mais ferramentas estão faltando.${RESET}"
        echo -e "${YELLOW}[!] Por favor, execute o script com a flag '--install' para instalá-las.${RESET}"
        exit 1
    fi
    echo -e "${GREEN}[✔] Todas as ferramentas necessárias foram encontradas.${RESET}"
}


# === PROCESSAMENTO DOS ARGUMENTOS DA LINHA DE COMANDO ===
DOMAIN=""
while [[ "$#" -gt 0 ]]; do
    case $1 in
        -d|--domain) DOMAIN="$2"; shift ;;
        --install) install_dependencies ;;
        -h|--help) usage ;;
        *) echo "Opção desconhecida: $1"; usage ;;
    esac
    shift
done

# Checagem de segurança: não rodar o scan como root
if [ "$EUID" -eq 0 ] && [[ "$1" != "--install" ]]; then
  echo -e "${RED}[✖] Erro: Por razões de segurança, não execute o scan de reconhecimento como usuário root.${RESET}"
  exit 1
fi

if [ -z "$DOMAIN" ]; then
    # Se o domínio for vazio, mas a flag --install não foi passada, mostre o erro.
    # Isso evita que a mensagem de erro apareça quando o objetivo é apenas instalar.
    if [[ "$1" != "--install" ]]; then
        echo -e "${RED}[✖] Erro: O domínio é obrigatório.${RESET}"
        usage
    fi
fi

# === INÍCIO DO SCRIPT DE RECONHECIMENTO ===
# Verifica as ferramentas antes de criar diretórios e começar o scan
check_tools

# Create output directory (can be mounted from host)
mkdir -p /app/output
cd /app/output

OUTPUT_DIR="recon-$DOMAIN-$(date +%F)"
mkdir -p "$OUTPUT_DIR"/{urls,hosts,vulns,js}

LOG_FILE="$OUTPUT_DIR/recon.log"
exec > >(tee -a ${LOG_FILE}) 2>&1

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
echo -e "${GREEN}[✔] Subdomínios coletados: $(wc -l < "$OUTPUT_DIR/subdomains.txt")${RESET}"

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
echo -e "${GREEN}[✔] Hosts vivos: $(wc -l < "$OUTPUT_DIR/hosts/alive.txt")${RESET}"

# 5️⃣ Coleta de URLs (Wayback Machine e GAU)
print_banner "ETAPA 5: Coletando URLs de Fontes Históricas"
(
    cat "$OUTPUT_DIR/hosts/alive.txt" | waybackurls
    cat "$OUTPUT_DIR/hosts/alive.txt" | gau -b png,jpg,gif,svg,css,js,woff,woff2 -t 20
) | sort -u | anew "$OUTPUT_DIR/urls.txt"
echo -e "${GREEN}[✔] URLs coletadas: $(wc -l < "$OUTPUT_DIR/urls.txt")${RESET}"

# 6️⃣ Análise de Arquivos JavaScript
print_banner "ETAPA 6: Analisando Arquivos JavaScript em busca de Endpoints"
grep '\.js$' "$OUTPUT_DIR/urls.txt" | httpx -status-code -mc 200 -content-type | grep 'javascript' | cut -d ' ' -f1 | getJS --complete > "$OUTPUT_DIR/js/endpoints.txt"
echo -e "${GREEN}[✔] Endpoints extraídos de arquivos JS.${RESET}"

# 7️⃣ Escaneamento de Vulnerabilidades com Nuclei
print_banner "ETAPA 7: Escaneando Vulnerabilidades com Nuclei"
nuclei -l "$OUTPUT_DIR/hosts/alive.txt" -t "technologies,cves,cnvd,default-logins,misconfigurations,vulnerabilities" -severity low,medium,high,critical -o "$OUTPUT_DIR/vulns/nuclei.txt"
echo -e "${GREEN}[✔] Nuclei scan concluído!${RESET}"

# === FIM ===
print_banner "Recon FINALIZADO para: $DOMAIN"
echo -e "Resultados completos salvos no diretório: ${BOLD}$OUTPUT_DIR${RESET}"
echo -e "Log de execução: ${BOLD}${LOG_FILE}${RESET}"


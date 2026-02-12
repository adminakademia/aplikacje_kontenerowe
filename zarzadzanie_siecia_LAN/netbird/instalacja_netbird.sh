#!/bin/bash
# =============================================================================
# Skrypt instalacji samodzielnie utrzymywanego NetBird z Zitadel
# Utworzony dla OS: Debian 13 (Trixie)
# =============================================================================
# Skrypt wykonuje pełną instalację serwera NetBird od zera:
#   1. Konfiguracja systemu (hostname, pakiety)
#   2. Konfiguracja firewalla (UFW)
#   3. Instalacja Docker
#   4. Instalacja NetBird (oficjalny skrypt getting-started-with-zitadel.sh)
#   5. Weryfikacja końcowa
# =============================================================================

set -euo pipefail

# !!!!!! Konfiguracja !!!!!! #

# Skonfiguruj parametry poniżej przed uruchomieniem skryptu:
HOSTNAME="vm-netbird"                   # Wpisz nazwę hosta
NETBIRD_DOMAIN="netbird.jojeadmin.pl"   # Domena DNS, pod którą ma działać NetBird
NETBIRD_DIR="/netbird"                  # Wskaż katalog roboczy — tu trafią docker-compose.yml i inne pliki konfiguracyjne


TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="/var/log/netbird-install_${TIMESTAMP}.log"

# Porty do odblokowania w zaporze ogniowej UFW
UFW_TCP_PORTS="22 80 443 33073 10000 33080"
UFW_UDP_PORTS="3478 49152:65535"

# Pakiety systemowe
BASE_PACKAGES=(mc sudo jq curl htop cron rsync logrotate ca-certificates gnupg)

# --- Kolory ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# --- Funkcje pomocnicze ---
log()    { echo -e "${GREEN}[$(date '+%H:%M:%S')] [INFO]${NC} $*" | tee -a "$LOG_FILE"; }
warn()   { echo -e "${YELLOW}[$(date '+%H:%M:%S')] [WARN]${NC} $*" | tee -a "$LOG_FILE"; }
err()    { echo -e "${RED}[$(date '+%H:%M:%S')] [ERROR]${NC} $*" | tee -a "$LOG_FILE" >&2; }
header() { echo -e "\n${CYAN}${BOLD}=== $* ===${NC}" | tee -a "$LOG_FILE"; }

abort() {
    err "$1"
    err "Skrypt przerwany. Log: ${LOG_FILE}"
    exit 1
}

confirm() {
    local msg="${1:-Kontynuować?}"
    read -r -p "$(echo -e "${YELLOW}${msg} [t/N]: ${NC}")" answer </dev/tty || answer="N"
    [[ "${answer,,}" == "t" ]]
}

retry() {
    local retries="${1}"
    local delay="${2}"
    shift 2
    local attempt=1

    while [[ $attempt -le $retries ]]; do
        if "$@"; then
            return 0
        fi
        warn "Komenda nie powiodła się (próba ${attempt}/${retries}). Ponawiam za ${delay}s..."
        sleep "$delay"
        attempt=$((attempt + 1))
    done
    return 1
}

cleanup_on_error() {
    local exit_code=$?
    if [[ $exit_code -ne 0 ]]; then
        err "Skrypt zakończył się błędem (kod: ${exit_code})."
        err "Sprawdź log: ${LOG_FILE}"
        err "Ostatni ukończony etap: ${CURRENT_STAGE:-nieznany}"
    fi
}
trap cleanup_on_error EXIT

CURRENT_STAGE="inicjalizacja"

# Dane logowania (uzupełniane automatycznie po instalacji NetBird)
NETBIRD_DASHBOARD_URL=""
NETBIRD_ADMIN_USER=""
NETBIRD_ADMIN_PASS=""

# =============================================================================
# ETAP 0: Walidacja wstępna
# =============================================================================
preflight_checks() {
    header "ETAP 0: Walidacja wstępna"
    CURRENT_STAGE="walidacja wstępna"

    # Root check
    if [[ $EUID -ne 0 ]]; then
        abort "Skrypt musi być uruchomiony jako root."
    fi

    # Debian check
    if [[ ! -f /etc/os-release ]]; then
        abort "Nie można określić systemu operacyjnego."
    fi

    source /etc/os-release
    if [[ "$ID" != "debian" ]]; then
        abort "Skrypt przeznaczony dla Debiana. Wykryto: ${ID}"
    fi
    log "System: ${PRETTY_NAME}"

    # Sprawdzenie domeny
    if [[ -z "$NETBIRD_DOMAIN" ]]; then
        abort "Zmienna NETBIRD_DOMAIN nie może być pusta. Ustaw domenę DNS w sekcji konfiguracji."
    fi
    log "Domena NetBird: ${NETBIRD_DOMAIN}"

    # Sprawdzenie DNS — czy domena wskazuje na ten serwer
    local resolved_ip
    resolved_ip=$(dig +short "$NETBIRD_DOMAIN" 2>/dev/null | tail -1) || true
    if [[ -n "$resolved_ip" ]]; then
        log "DNS ${NETBIRD_DOMAIN} -> ${resolved_ip}"
    else
        warn "Nie udało się rozwiązać domeny ${NETBIRD_DOMAIN}."
        warn "Upewnij się, że rekordy DNS (A/AAAA) wskazują na adres IP tego serwera."
        if ! confirm "Kontynuować mimo braku rozwiązania DNS?"; then
            abort "Przerwano — domena nie jest skonfigurowana."
        fi
    fi

    # Sprawdzenie połączenia z internetem
    if ! wget -q --spider --timeout=10 https://deb.debian.org 2>/dev/null && \
       ! bash -c 'echo >/dev/tcp/deb.debian.org/443' 2>/dev/null; then
        abort "Brak połączenia z internetem. Wymagane do instalacji pakietów."
    fi
    log "Połączenie z internetem: OK"

    # Sprawdzenie wolnego miejsca (min. 5GB)
    local available_kb
    available_kb=$(df / --output=avail | tail -1 | tr -d ' ')
    if [[ "$available_kb" -lt 5242880 ]]; then
        warn "Mało wolnego miejsca na dysku (< 5GB)."
        if ! confirm "Kontynuować mimo mało miejsca?"; then
            abort "Przerwano — za mało miejsca na dysku."
        fi
    fi
    log "Wolne miejsce na dysku: $(df -h / --output=avail | tail -1 | tr -d ' ')"

    # Sprawdzenie czy Docker/NetBird nie są już zainstalowane
    if command -v docker &>/dev/null && docker compose ps 2>/dev/null | grep -qi netbird; then
        warn "Wykryto działające kontenery NetBird. Możliwe, że NetBird jest już zainstalowany."
        if ! confirm "Kontynuować mimo to?"; then
            abort "Przerwano — NetBird może być już zainstalowany."
        fi
    fi

    log "Walidacja wstępna zakończona pomyślnie."
}

# =============================================================================
# ETAP 1: Konfiguracja systemu
# =============================================================================
configure_system() {
    header "ETAP 1: Konfiguracja systemu"
    CURRENT_STAGE="konfiguracja systemu"

    # Hostname
    local current_hostname
    current_hostname=$(hostname)
    if [[ "$current_hostname" != "$HOSTNAME" ]]; then
        log "Ustawianie hostname: ${HOSTNAME}"
        hostnamectl set-hostname "$HOSTNAME"
        log "Hostname zmieniony: ${current_hostname} -> ${HOSTNAME}"
    else
        log "Hostname już ustawiony: ${HOSTNAME}"
    fi

    # Aktualizacja systemu
    log "Aktualizacja systemu..."
    export DEBIAN_FRONTEND=noninteractive
    if ! retry 3 10 apt-get update -qq; then
        abort "Nie udało się zaktualizować listy pakietów."
    fi

    if ! apt-get upgrade -y -qq 2>&1 | tee -a "$LOG_FILE"; then
        warn "Aktualizacja pakietów zakończyła się z ostrzeżeniami."
    fi
    log "System zaktualizowany."

    # Instalacja pakietów bazowych
    log "Instalacja pakietów bazowych: ${BASE_PACKAGES[*]}"
    if ! apt-get install -y -qq "${BASE_PACKAGES[@]}" 2>&1 | tee -a "$LOG_FILE"; then
        abort "Nie udało się zainstalować pakietów bazowych."
    fi
    log "Pakiety bazowe zainstalowane."
}

# =============================================================================
# ETAP 2: Firewall (UFW)
# =============================================================================
configure_ufw() {
    header "ETAP 2: Konfiguracja firewalla (UFW)"
    CURRENT_STAGE="konfiguracja UFW"

    if ! command -v ufw &>/dev/null; then
        log "Instalacja UFW..."
        apt-get install -y -qq ufw 2>&1 | tee -a "$LOG_FILE"
    fi

    # Reset reguł (czysta konfiguracja)
    log "Konfiguracja reguł UFW..."
    ufw --force reset >> "$LOG_FILE" 2>&1

    # Domyślna polityka
    ufw default deny incoming >> "$LOG_FILE" 2>&1
    ufw default allow outgoing >> "$LOG_FILE" 2>&1

    # Reguły TCP
    for port in $UFW_TCP_PORTS; do
        log "  Otwieranie TCP: ${port}"
        ufw allow "$port"/tcp >> "$LOG_FILE" 2>&1 || ufw allow "$port" >> "$LOG_FILE" 2>&1
    done

    # Reguły UDP
    for port in $UFW_UDP_PORTS; do
        log "  Otwieranie UDP: ${port}"
        ufw allow "$port"/udp >> "$LOG_FILE" 2>&1
    done

    # Włączenie UFW
    ufw --force enable >> "$LOG_FILE" 2>&1
    log "UFW włączony."

    # Status
    log "Status UFW:"
    ufw status verbose 2>&1 | tee -a "$LOG_FILE"
}

# =============================================================================
# ETAP 3: Instalacja Docker
# =============================================================================
install_docker() {
    header "ETAP 3: Instalacja Docker"
    CURRENT_STAGE="instalacja Docker"

    # Sprawdzenie czy Docker już zainstalowany
    if command -v docker &>/dev/null && docker info &>/dev/null 2>&1; then
        local docker_version
        docker_version=$(docker --version)
        log "Docker już zainstalowany: ${docker_version}"

        if docker compose version &>/dev/null 2>&1; then
            log "Docker Compose plugin: $(docker compose version)"
            return 0
        else
            warn "Docker Compose plugin nie jest zainstalowany. Kontynuuję instalację..."
        fi
    fi

    # Dodanie klucza GPG Docker
    log "Dodawanie klucza GPG Docker..."
    install -m 0755 -d /etc/apt/keyrings

    if ! retry 3 5 curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc; then
        abort "Nie udało się pobrać klucza GPG Docker."
    fi
    chmod a+r /etc/apt/keyrings/docker.asc

    # Dodanie repozytorium Docker
    log "Dodawanie repozytorium Docker..."
    source /etc/os-release
    tee /etc/apt/sources.list.d/docker.sources > /dev/null <<EOF
Types: deb
URIs: https://download.docker.com/linux/debian
Suites: ${VERSION_CODENAME}
Components: stable
Signed-By: /etc/apt/keyrings/docker.asc
EOF

    # Instalacja Docker
    log "Instalacja pakietów Docker..."
    if ! retry 3 10 apt-get update -qq; then
        abort "Nie udało się zaktualizować listy pakietów po dodaniu repo Docker."
    fi

    local docker_packages=(docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin)
    if ! apt-get install -y -qq "${docker_packages[@]}" 2>&1 | tee -a "$LOG_FILE"; then
        abort "Nie udało się zainstalować Docker."
    fi

    # Weryfikacja
    if ! docker info &>/dev/null 2>&1; then
        log "Uruchamianie Docker daemon..."
        systemctl enable --now docker
        sleep 3
    fi

    if ! docker info &>/dev/null 2>&1; then
        abort "Docker daemon nie działa po instalacji."
    fi

    if ! docker compose version &>/dev/null 2>&1; then
        abort "Docker Compose plugin nie jest dostępny po instalacji."
    fi

    log "Docker zainstalowany: $(docker --version)"
    log "Docker Compose: $(docker compose version)"
}

# =============================================================================
# ETAP 4: Instalacja NetBird
# =============================================================================
install_netbird() {
    header "ETAP 4: Instalacja NetBird"
    CURRENT_STAGE="instalacja NetBird"

    # Utworzenie katalogu roboczego
    if [[ ! -d "$NETBIRD_DIR" ]]; then
        log "Tworzenie katalogu roboczego: ${NETBIRD_DIR}"
        mkdir -p "$NETBIRD_DIR"
    fi

    log "Katalog roboczy: ${NETBIRD_DIR}"
    log "Domena: ${NETBIRD_DOMAIN}"
    log "Pobieranie i uruchamianie oficjalnego skryptu instalacyjnego NetBird..."
    log "Źródło: https://github.com/netbirdio/netbird/releases/latest/download/getting-started-with-zitadel.sh"

    export NETBIRD_DOMAIN="$NETBIRD_DOMAIN"

    if ! curl -fsSL https://github.com/netbirdio/netbird/releases/latest/download/getting-started-with-zitadel.sh -o /tmp/netbird-install.sh; then
        abort "Nie udało się pobrać skryptu instalacyjnego NetBird."
    fi

    chmod +x /tmp/netbird-install.sh
    log "Skrypt instalacyjny pobrany. Uruchamianie z katalogu ${NETBIRD_DIR}..."

    # Uruchomienie z katalogu NETBIRD_DIR — oficjalny skrypt generuje pliki
    # (docker-compose.yml, Caddyfile, *.env, management.json, itp.)
    # w bieżącym katalogu roboczym
    cd "$NETBIRD_DIR"
    if ! bash /tmp/netbird-install.sh 2>&1 | tee -a "$LOG_FILE"; then
        abort "Skrypt instalacyjny NetBird zakończył się błędem."
    fi

    rm -f /tmp/netbird-install.sh

    # Odczytanie danych logowania z wyniku instalacji
    NETBIRD_DASHBOARD_URL=$(grep 'dashboard at' "$LOG_FILE" | tail -1 | sed 's/.*dashboard at //' | tr -d ' ') || true
    NETBIRD_ADMIN_USER=$(grep 'Username:' "$LOG_FILE" | tail -1 | awk '{print $NF}') || true
    NETBIRD_ADMIN_PASS=$(grep 'Password:' "$LOG_FILE" | tail -1 | awk '{print $NF}') || true

    log "Instalacja NetBird zakończona. Pliki w: ${NETBIRD_DIR}"
}

# =============================================================================
# ETAP 5: Weryfikacja końcowa
# =============================================================================
final_verification() {
    header "ETAP 5: Weryfikacja końcowa"
    CURRENT_STAGE="weryfikacja końcowa"

    local errors=0

    # Docker
    log "Sprawdzanie Docker..."
    if docker info &>/dev/null 2>&1; then
        log "  Docker: OK"
    else
        err "  Docker: NIE DZIAŁA"
        errors=$((errors + 1))
    fi

    # Kontenery NetBird
    log "Sprawdzanie kontenerów NetBird..."
    if [[ -f "${NETBIRD_DIR}/docker-compose.yml" ]]; then
        cd "$NETBIRD_DIR"
        local services
        mapfile -t services < <(docker compose config --services 2>/dev/null)
        local running=0
        local total=${#services[@]}

        for svc in "${services[@]}"; do
            local state
            state=$(docker compose ps --format '{{.State}}' "$svc" 2>/dev/null || echo "missing")
            if [[ "$state" == "running" ]]; then
                log "  ${svc}: OK"
                running=$((running + 1))
            else
                err "  ${svc}: ${state}"
                errors=$((errors + 1))
            fi
        done
        log "  Kontenery: ${running}/${total} działają."
    else
        warn "  Nie znaleziono ${NETBIRD_DIR}/docker-compose.yml — pomijam sprawdzanie kontenerów."
    fi

    # UFW
    log "Sprawdzanie UFW..."
    if ufw status | grep -q "Status: active"; then
        log "  UFW: aktywny"
    else
        warn "  UFW: nieaktywny"
        errors=$((errors + 1))
    fi

    # Sprawdzenie portów
    log "Sprawdzanie nasłuchujących portów..."
    ss -tlnp | grep -E ':(80|443|8080|33073|10000|33080|3478) ' 2>&1 | tee -a "$LOG_FILE" || true

    # Podsumowanie
    header "PODSUMOWANIE INSTALACJI"
    log "Hostname:    $(hostname)"
    log "System:      $(grep PRETTY_NAME /etc/os-release | cut -d= -f2 | tr -d '"')"
    log "Docker:      $(docker --version 2>/dev/null || echo 'N/A')"
    log "Compose:     $(docker compose version 2>/dev/null || echo 'N/A')"
    log "Domena:      ${NETBIRD_DOMAIN}"
    log "UFW:         $(ufw status | head -1)"
    if [[ -f "${NETBIRD_DIR}/docker-compose.yml" ]]; then
        log "Kontenery:   ${running:-0}/${total:-0} działają"
        log "Katalog:     ${NETBIRD_DIR}"
    fi
    log "Log:         ${LOG_FILE}"

    if [[ $errors -gt 0 ]]; then
        warn "Instalacja zakończona z ${errors} problemami. Sprawdź log."
    else
        log "Instalacja zakończona pomyślnie!"
    fi

    # Dane logowania do panelu NetBird
    if [[ -n "$NETBIRD_DASHBOARD_URL" || -n "$NETBIRD_ADMIN_USER" || -n "$NETBIRD_ADMIN_PASS" ]]; then
        header "DANE LOGOWANIA DO PANELU NETBIRD"
        log "Panel dostępny pod adresem: ${NETBIRD_DASHBOARD_URL:-N/A}"
        log "Nazwa użytkownika:          ${NETBIRD_ADMIN_USER:-N/A}"
        log "Hasło:                      ${NETBIRD_ADMIN_PASS:-N/A}"
    else
        warn "Nie udało się odczytać danych logowania z wyniku instalacji."
        warn "Sprawdź log: ${LOG_FILE}"
    fi
}

# =============================================================================
# MAIN
# =============================================================================
main() {
    header "NetBird Installation — Start"
    log "Data: $(date)"
    log "Log: ${LOG_FILE}"

    echo ""
    echo -e "${BOLD}Ten skrypt wykona następujące operacje:${NC}"
    echo "  1. Walidacja wstępna (system, sieć, DNS)"
    echo "  2. Konfiguracja systemu (hostname: ${HOSTNAME}, pakiety)"
    echo "  3. Konfiguracja firewalla (UFW)"
    echo "  4. Instalacja Docker"
    echo "  5. Instalacja NetBird (domena: ${NETBIRD_DOMAIN}, katalog: ${NETBIRD_DIR})"
    echo "  6. Weryfikacja końcowa"
    echo ""

    if ! confirm "Rozpocząć instalację?"; then
        log "Przerwano przez użytkownika."
        exit 0
    fi

    preflight_checks
    configure_system
    configure_ufw
    install_docker
    install_netbird
    final_verification

    header "GOTOWE"
}

main "$@"

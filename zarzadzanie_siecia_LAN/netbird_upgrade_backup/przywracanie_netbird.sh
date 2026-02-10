#!/bin/bash
# ========================================================================================
# Skrypt przywracania dla samodzielnie utrzymywanego NetBird
# Utworzony dla OS: Debian 13 (Trixie)
# ========================================================================================
# WYMAGANIA WSTĘPNE (wykonaj ręcznie przed uruchomieniem skryptu):
#   1. Utwórz katalogi jako użytkownik "root" (w pierwszym przypadki zamiast netbird 
#      możesz utworzyć inny katalog - wtedy poniżej podaj go w zmiennej "NETBIRD_DIR"):  
#      mkdir /netbird 
#      mkdir /var/lib/docker/volumes/
#   2. Przekopiuj wolumeny Docker:  /var/lib/docker/volumes/netbird_*
#   3. Przekopiuj katalog z plikami NetBird:  /netbird/
#      Zawierający: docker-compose.yml, Caddyfile, dashboard.env, relay.env,
#                   management.json, turnserver.conf, zitadel.env, zdb.env,
#                   machinekey/
# ========================================================================================

set -euo pipefail

# --- Konfiguracja ---
NETBIRD_DIR="/netbird"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="/var/log/netbird-recovery_${TIMESTAMP}.log"
HOSTNAME="vm-netbird"          # Nadaj nazwę hosta
INSTALL_CROWDSEC=true          # Jeżeli chcesz też zainstalować CrowdSec: true = instaluj CrowdSec, false = pomiń instalację
CROWDSEC_PORT=8081             # Zmieniamy port z 8080 (konflikt z NetBird) - możesz podać w razie potrzeby inny port
CROWDSEC_ENROLL_KEY="1234567890" # Tutaj wpisz odczytany w panelu web CrowdSec klucz podpinający ten system

# Porty do odblokowania w zaporze ogniowej UFW
UFW_TCP_PORTS="22 80 443 33073 10000 33080"
UFW_UDP_PORTS="3478 49152:65535"

# Pliki konfiguracyjne NetBird
CONFIG_FILES=(
    docker-compose.yml
    Caddyfile
    dashboard.env
    relay.env
    management.json
    turnserver.conf
    zitadel.env
    zdb.env
)

SENSITIVE_FILES=(dashboard.env relay.env zitadel.env zdb.env)
PUBLIC_FILES=(docker-compose.yml Caddyfile management.json turnserver.conf)

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

    # Sprawdzenie katalogu NetBird
    if [[ ! -d "$NETBIRD_DIR" ]]; then
        abort "Katalog ${NETBIRD_DIR} nie istnieje. Przekopiuj dane z backupu."
    fi

    local missing_files=()
    for file in "${CONFIG_FILES[@]}"; do
        if [[ ! -f "${NETBIRD_DIR}/${file}" ]]; then
            missing_files+=("$file")
        fi
    done

    if [[ ! -d "${NETBIRD_DIR}/machinekey" ]]; then
        missing_files+=("machinekey/")
    fi

    if [[ ${#missing_files[@]} -gt 0 ]]; then
        err "Brakujące pliki/katalogi w ${NETBIRD_DIR}:"
        for f in "${missing_files[@]}"; do
            err "  - ${f}"
        done
        abort "Uzupełnij brakujące pliki z backupu przed kontynuacją."
    fi

    log "Wszystkie pliki konfiguracyjne obecne w ${NETBIRD_DIR}."

    # Sprawdzenie wolumenów Docker
    local volumes_found
    volumes_found=$(find /var/lib/docker/volumes/ -maxdepth 1 -name '*netbird_*' -type d 2>/dev/null | wc -l)
    if [[ "$volumes_found" -eq 0 ]]; then
        warn "Nie znaleziono wolumenów netbird_* w /var/lib/docker/volumes/"
        warn "Upewnij się, że wolumeny zostały przekopiowane z backupu."
        if ! confirm "Kontynuować mimo braku wolumenów?"; then
            abort "Przerwano — brak wolumenów Docker."
        fi
    else
        log "Znaleziono ${volumes_found} wolumenów netbird_* w /var/lib/docker/volumes/"
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
# ETAP 4: Przygotowanie plików NetBird
# =============================================================================
prepare_netbird_files() {
    header "ETAP 4: Przygotowanie plików NetBird"
    CURRENT_STAGE="przygotowanie plików NetBird"

    # Weryfikacja docker-compose.yml
    log "Walidacja docker-compose.yml..."
    cd "$NETBIRD_DIR"
    if docker compose config --quiet 2>&1 | tee -a "$LOG_FILE"; then
        log "docker-compose.yml: poprawny."
    else
        warn "docker-compose.yml: walidacja zwróciła ostrzeżenia (sprawdź log)."
    fi

    # Dostosowanie nazw wolumenów Docker do katalogu NETBIRD_DIR
    # Docker Compose nadaje wolumenom przedrostek = nazwa katalogu roboczego.
    # Jeśli backup powstał z /root/, wolumeny mają przedrostek "root_",
    # ale skrypt uruchamia compose z NETBIRD_DIR, więc oczekiwany przedrostek
    # musi się zgadzać — w przeciwnym razie Docker utworzy nowe puste wolumeny.
    local docker_volumes="/var/lib/docker/volumes"
    local expected_prefix
    expected_prefix=$(basename "$NETBIRD_DIR")
    log "Sprawdzanie przedrostków wolumenów Docker (oczekiwany: ${expected_prefix})..."

    local volumes_to_rename=()
    while IFS= read -r -d '' vol_dir; do
        local vol_name
        vol_name=$(basename "$vol_dir")
        local current_prefix="${vol_name%%_netbird_*}"
        if [[ "$current_prefix" != "$expected_prefix" ]]; then
            volumes_to_rename+=("$vol_name")
        fi
    done < <(find "$docker_volumes" -maxdepth 1 -name '*_netbird_*' -type d -print0 2>/dev/null)

    if [[ ${#volumes_to_rename[@]} -gt 0 ]]; then
        log "Znaleziono ${#volumes_to_rename[@]} wolumenów z innym przedrostkiem. Zmiana nazw..."

        # Zatrzymanie Docker przed zmianą nazw wolumenów
        log "Zatrzymywanie Docker daemon..."
        systemctl stop docker

        for vol_name in "${volumes_to_rename[@]}"; do
            local suffix="${vol_name#*_netbird_}"
            local new_name="${expected_prefix}_netbird_${suffix}"

            if [[ -d "${docker_volumes}/${new_name}" ]]; then
                warn "  Wolumen ${new_name} już istnieje — pomijam zmianę nazwy ${vol_name}."
                continue
            fi

            log "  ${vol_name} -> ${new_name}"
            mv "${docker_volumes}/${vol_name}" "${docker_volumes}/${new_name}"
        done

        # Ponowne uruchomienie Docker
        log "Uruchamianie Docker daemon..."
        systemctl start docker
        sleep 3

        if ! docker info &>/dev/null 2>&1; then
            abort "Docker daemon nie uruchomił się po zmianie nazw wolumenów."
        fi
        log "Nazwy wolumenów dostosowane do przedrostka: ${expected_prefix}"
    else
        log "Przedrostki wolumenów zgodne (${expected_prefix}) — brak zmian."
    fi

    # Nadanie uprawnień plikom konfiguracyjnym
    log "Ustawianie uprawnień plików konfiguracyjnych..."

    # Pliki wrażliwe (.env) — 600 (rw-------)
    for file in "${SENSITIVE_FILES[@]}"; do
        if [[ -f "${NETBIRD_DIR}/${file}" ]]; then
            chmod 600 "${NETBIRD_DIR}/${file}"
            log "  ${file}: 600"
        fi
    done

    # Pliki publiczne — 644 (rw-r--r--)
    for file in "${PUBLIC_FILES[@]}"; do
        if [[ -f "${NETBIRD_DIR}/${file}" ]]; then
            chmod 644 "${NETBIRD_DIR}/${file}"
            log "  ${file}: 644"
        fi
    done

    # Plik .env — 644 (rw-r--r--)
    if [[ -f "${NETBIRD_DIR}/.env" ]]; then
        chmod 644 "${NETBIRD_DIR}/.env"
        log "  .env: 644"
    fi

    # Katalog machinekey — 700 (rwx------)
    if [[ -d "${NETBIRD_DIR}/machinekey" ]]; then
        chmod 700 "${NETBIRD_DIR}/machinekey"
        log "  machinekey/: 700"
    fi

    # Token Zitadel — 700 (rwx------), właściciel 1000:1000
    if [[ -f "${NETBIRD_DIR}/machinekey/zitadel-admin-sa.token" ]]; then
        chmod 700 "${NETBIRD_DIR}/machinekey/zitadel-admin-sa.token"
        chown root:root "${NETBIRD_DIR}/machinekey/zitadel-admin-sa.token"
        log "  machinekey/zitadel-admin-sa.token: 700 (root:root)"
    fi

    log "Uprawnienia plików konfiguracyjnych ustawione."

    # Nadanie uprawnień wolumenom Docker
    local docker_volumes="/var/lib/docker/volumes"
    log "Ustawianie uprawnień wolumenów Docker..."

    # Wolumen management (root:root, katalogi 755, pliki 644)
    local mgmt_vol
    mgmt_vol=$(find "$docker_volumes" -maxdepth 1 -name '*netbird_management' -type d 2>/dev/null | head -1)
    if [[ -n "$mgmt_vol" && -d "${mgmt_vol}/_data" ]]; then
        chown -R root:root "${mgmt_vol}/_data"
        find "${mgmt_vol}/_data" -type d -exec chmod 755 {} \;
        find "${mgmt_vol}/_data" -type f -exec chmod 644 {} \;
        log "  $(basename "$mgmt_vol")/_data: root:root, katalogi 755, pliki 644"
    else
        warn "  Nie znaleziono wolumenu *netbird_management"
    fi

    # Wolumen zdb_data — PostgreSQL (70:70, katalogi 700, pliki 600)
    local zdb_vol
    zdb_vol=$(find "$docker_volumes" -maxdepth 1 -name '*netbird_zdb_data' -type d 2>/dev/null | head -1)
    if [[ -n "$zdb_vol" && -d "${zdb_vol}/_data" ]]; then
        chown -R 70:70 "${zdb_vol}/_data"
        find "${zdb_vol}/_data" -type d -exec chmod 700 {} \;
        find "${zdb_vol}/_data" -type f -exec chmod 600 {} \;
        log "  $(basename "$zdb_vol")/_data: 70:70, katalogi 700, pliki 600"
    else
        warn "  Nie znaleziono wolumenu *netbird_zdb_data"
    fi

    log "Uprawnienia wolumenów Docker ustawione."
    log "Pliki NetBird przygotowane."
}

# =============================================================================
# ETAP 5: Uruchomienie NetBird
# =============================================================================
start_netbird() {
    header "ETAP 5: Uruchomienie NetBird"
    CURRENT_STAGE="uruchomienie NetBird"

    cd "$NETBIRD_DIR"

    # Pull obrazów
    log "Pobieranie obrazów Docker..."
    if ! retry 3 15 docker compose pull 2>&1 | tee -a "$LOG_FILE"; then
        abort "Nie udało się pobrać obrazów Docker."
    fi

    # Uruchomienie kontenerów
    log "Uruchamianie kontenerów NetBird..."
    if ! docker compose up -d 2>&1 | tee -a "$LOG_FILE"; then
        abort "Nie udało się uruchomić kontenerów."
    fi

    # Healthcheck
    log "Oczekiwanie na uruchomienie serwisów (max 180s)..."
    local elapsed=0
    local timeout=180
    local interval=5
    local services
    mapfile -t services < <(docker compose config --services 2>/dev/null)

    while [[ $elapsed -lt $timeout ]]; do
        local all_running=true

        for svc in "${services[@]}"; do
            local state
            state=$(docker compose ps --format '{{.State}}' "$svc" 2>/dev/null || echo "missing")
            if [[ "$state" != "running" ]]; then
                all_running=false
                break
            fi
        done

        if $all_running; then
            log "Wszystkie serwisy (${#services[@]}) działają poprawnie!"
            docker compose ps 2>&1 | tee -a "$LOG_FILE"
            return 0
        fi

        sleep "$interval"
        ((elapsed += interval))
        # Postęp co 30s
        if (( elapsed % 30 == 0 )); then
            log "  Oczekiwanie... (${elapsed}s/${timeout}s)"
        fi
    done

    err "Nie wszystkie serwisy uruchomiły się w ciągu ${timeout}s."
    err "Status kontenerów:"
    docker compose ps 2>&1 | tee -a "$LOG_FILE"

    for svc in "${services[@]}"; do
        local state
        state=$(docker compose ps --format '{{.State}}' "$svc" 2>/dev/null || echo "unknown")
        if [[ "$state" != "running" ]]; then
            err "Logi serwisu ${svc} (ostatnie 50 linii):"
            docker compose logs --tail=50 "$svc" 2>&1 | tee -a "$LOG_FILE"
        fi
    done

    if ! confirm "Serwisy nie uruchomiły się w pełni. Kontynuować mimo to?"; then
        abort "Przerwano — serwisy NetBird nie działają."
    fi
}

# =============================================================================
# ETAP 6: Instalacja CrowdSec
# =============================================================================
install_crowdsec() {
    header "ETAP 6: Instalacja CrowdSec"
    CURRENT_STAGE="instalacja CrowdSec"

    # Instalacja repozytorium CrowdSec
    log "Dodawanie repozytorium CrowdSec..."
    if ! retry 3 5 bash -c 'curl -s https://install.crowdsec.net | sh' 2>&1 | tee -a "$LOG_FILE"; then
        warn "Nie udało się dodać repozytorium CrowdSec."
        if ! confirm "Pominąć instalację CrowdSec?"; then
            abort "Przerwano — nie udało się zainstalować CrowdSec."
        fi
        return 0
    fi

    # Instalacja CrowdSec
    log "Instalacja CrowdSec..."
    if ! apt-get install -y -qq crowdsec 2>&1 | tee -a "$LOG_FILE"; then
        warn "Nie udało się zainstalować CrowdSec."
        return 1
    fi

    # Instalacja firewall bouncer
    log "Instalacja CrowdSec Firewall Bouncer..."
    if ! apt-get install -y -qq crowdsec-firewall-bouncer-iptables 2>&1 | tee -a "$LOG_FILE"; then
        warn "Nie udało się zainstalować firewall bouncer."
    fi

    log "CrowdSec zainstalowany."
}

# =============================================================================
# ETAP 7: Konfiguracja CrowdSec (zmiana portu z 8080 na CROWDSEC_PORT)
# =============================================================================
configure_crowdsec() {
    header "ETAP 7: Konfiguracja CrowdSec (port ${CROWDSEC_PORT})"
    CURRENT_STAGE="konfiguracja CrowdSec"

    local config_file="/etc/crowdsec/config.yaml"
    local creds_file="/etc/crowdsec/local_api_credentials.yaml"
    local bouncer_file="/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml"

    # Sprawdzenie czy port 8080 jest zajęty (przez NetBird)
    if ss -tlnp | grep -q ':8080 '; then
        log "Port 8080 zajęty (NetBird). Zmiana portu CrowdSec na ${CROWDSEC_PORT}."
    else
        log "Port 8080 wolny, ale zmieniam na ${CROWDSEC_PORT} prewencyjnie."
    fi

    # Zmiana portu w config.yaml
    if [[ -f "$config_file" ]]; then
        log "Modyfikacja ${config_file}..."
        if grep -q 'listen_uri' "$config_file"; then
            sed -i "s|listen_uri:.*|listen_uri: 127.0.0.1:${CROWDSEC_PORT}|" "$config_file"
        else
            warn "Nie znaleziono 'listen_uri' w ${config_file}. Sprawdź ręcznie."
        fi
    else
        warn "Brak pliku ${config_file}"
    fi

    # Zmiana URL w local_api_credentials.yaml
    if [[ -f "$creds_file" ]]; then
        log "Modyfikacja ${creds_file}..."
        sed -i "s|url:.*|url: http://127.0.0.1:${CROWDSEC_PORT}/|" "$creds_file"
    else
        warn "Brak pliku ${creds_file}"
    fi

    # Zmiana URL w bouncer config
    if [[ -f "$bouncer_file" ]]; then
        log "Modyfikacja ${bouncer_file}..."
        sed -i "s|api_url:.*|api_url: http://127.0.0.1:${CROWDSEC_PORT}/|" "$bouncer_file"
    else
        warn "Brak pliku ${bouncer_file}"
    fi

    # Restart serwisów CrowdSec
    log "Restartowanie CrowdSec..."
    systemctl restart crowdsec 2>&1 | tee -a "$LOG_FILE" || warn "Nie udało się zrestartować crowdsec."

    sleep 3

    if systemctl is-active --quiet crowdsec; then
        log "CrowdSec działa na porcie ${CROWDSEC_PORT}."
    else
        warn "CrowdSec nie uruchomił się poprawnie. Sprawdź: journalctl -u crowdsec"
    fi

    # Restart firewall bouncer
    log "Restartowanie firewall bouncer..."
    systemctl enable --now crowdsec-firewall-bouncer 2>&1 | tee -a "$LOG_FILE" || \
        warn "Nie udało się uruchomić firewall bouncer."

    if systemctl is-active --quiet crowdsec-firewall-bouncer; then
        log "CrowdSec Firewall Bouncer działa."
    else
        warn "Firewall Bouncer nie uruchomił się. Sprawdź: journalctl -u crowdsec-firewall-bouncer"
    fi

    # Enroll do konsoli CrowdSec
    if [[ -n "$CROWDSEC_ENROLL_KEY" ]]; then
        log "Rejestracja w konsoli CrowdSec..."
        if cscli console enroll -e context "$CROWDSEC_ENROLL_KEY" 2>&1 | tee -a "$LOG_FILE"; then
            log "Rejestracja w konsoli CrowdSec zakończona."
        else
            warn "Nie udało się zarejestrować w konsoli CrowdSec."
        fi
    fi

    log "Konfiguracja CrowdSec zakończona."
}

# =============================================================================
# ETAP 8: Weryfikacja końcowa
# =============================================================================
final_verification() {
    header "ETAP 8: Weryfikacja końcowa"
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

    # UFW
    log "Sprawdzanie UFW..."
    if ufw status | grep -q "Status: active"; then
        log "  UFW: aktywny"
    else
        warn "  UFW: nieaktywny"
        errors=$((errors + 1))
    fi

    # CrowdSec
    if [[ "$INSTALL_CROWDSEC" == true ]]; then
        log "Sprawdzanie CrowdSec..."
        if systemctl is-active --quiet crowdsec 2>/dev/null; then
            log "  CrowdSec: OK (port ${CROWDSEC_PORT})"
        else
            warn "  CrowdSec: nie działa"
        fi

        if systemctl is-active --quiet crowdsec-firewall-bouncer 2>/dev/null; then
            log "  Firewall Bouncer: OK"
        else
            warn "  Firewall Bouncer: nie działa"
        fi
    else
        log "  CrowdSec: pominięty (INSTALL_CROWDSEC=false)"
    fi

    # Sprawdzenie portów
    log "Sprawdzanie nasłuchujących portów..."
    ss -tlnp | grep -E ':(80|443|8080|33073|10000|33080|3478|8081) ' 2>&1 | tee -a "$LOG_FILE" || true

    # Podsumowanie
    header "PODSUMOWANIE ODTWORZENIA"
    log "Hostname:    $(hostname)"
    log "System:      $(grep PRETTY_NAME /etc/os-release | cut -d= -f2 | tr -d '"')"
    log "Docker:      $(docker --version 2>/dev/null || echo 'N/A')"
    log "Compose:     $(docker compose version 2>/dev/null || echo 'N/A')"
    log "Kontenery:   ${running}/${total} działają"
    log "Katalog:     ${NETBIRD_DIR}"
    log "UFW:         $(ufw status | head -1)"
    if [[ "$INSTALL_CROWDSEC" == true ]]; then
        log "CrowdSec:    $(systemctl is-active crowdsec 2>/dev/null || echo 'N/A')"
    else
        log "CrowdSec:    pominięty"
    fi
    log "Log:         ${LOG_FILE}"

    if [[ $errors -gt 0 ]]; then
        warn "Odtworzenie zakończone z ${errors} problemami. Sprawdź log."
    else
        log "Odtworzenie zakończone pomyślnie!"
    fi
}

# =============================================================================
# MAIN
# =============================================================================
main() {
    header "NetBird Disaster Recovery — Start"
    log "Data: $(date)"
    log "Log: ${LOG_FILE}"

    echo ""
    echo -e "${BOLD}Ten skrypt wykona następujące operacje:${NC}"
    echo "  1. Walidacja wstępna (pliki, wolumeny, sieć) oraz konfiguracja systemu (hostname, pakiety)"
    echo "  2. Konfiguracja firewalla (UFW)"
    echo "  3. Instalacja Docker"
    echo "  4. Przygotowanie plików NetBird"
    echo "  5. Uruchomienie NetBird (docker compose up z ${NETBIRD_DIR})"
    if [[ "$INSTALL_CROWDSEC" == true ]]; then
        echo "  6-7. Instalacja i konfiguracja CrowdSec"
    else
        echo "  6-7. Instalacja i konfiguracja CrowdSec — POMINIĘTA (INSTALL_CROWDSEC=false)"
    fi
    echo "  8. Weryfikacja końcowa"
    echo ""

    if ! confirm "Rozpocząć odtwarzanie?"; then
        log "Przerwano przez użytkownika."
        exit 0
    fi

    preflight_checks
    configure_system
    configure_ufw
    install_docker
    prepare_netbird_files
    start_netbird

    if [[ "$INSTALL_CROWDSEC" == true ]]; then
        install_crowdsec
        configure_crowdsec
    else
        log "Instalacja CrowdSec pominięta (INSTALL_CROWDSEC=false)."
    fi

    final_verification

    header "GOTOWE"
}

main "$@"

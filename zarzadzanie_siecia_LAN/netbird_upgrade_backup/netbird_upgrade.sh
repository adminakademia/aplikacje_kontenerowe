#!/bin/bash
# Skrypt aktualizacji samodzielnie utrzymywanego NetBird
# Dokumentacja dot. aktualizacji:
# https://docs.netbird.io/selfhosted/maintenance/upgrade
# ------------------------------------------------


set -euo pipefail

# --- Konfiguracja ---
WORKDIR="/netbird"   # Wpisz ścieżkę katalogu w którym masz pliki zawierające: docker-compose.yml, Caddyfile, dashboard.env, relay.env,
#                   management.json, turnserver.conf, zitadel.env, zdb.env,
#                   machinekey/
BACKUP_DIR="${WORKDIR}/backup"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_VERSIONED="${BACKUP_DIR}/${TIMESTAMP}"
LOG_FILE="${WORKDIR}/netbird-update_${TIMESTAMP}.log"
COMPOSE_FILE="${WORKDIR}/docker-compose.yml"
HEALTHCHECK_TIMEOUT=180  # wpisz jak długo ma skrypt czekać na uruchomienie wszystkich serwisów po aktualizacji
HEALTHCHECK_INTERVAL=5

CONFIG_FILES=(
    docker-compose.yml
    Caddyfile
    zitadel.env
    dashboard.env
    turnserver.conf
    management.json
    relay.env
    zdb.env
)

# --- Kolory ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# --- Funkcje pomocnicze ---
log()  { echo -e "${GREEN}[$(date '+%H:%M:%S')] [INFO]${NC} $*" | tee -a "$LOG_FILE"; }
warn() { echo -e "${YELLOW}[$(date '+%H:%M:%S')] [WARN]${NC} $*" | tee -a "$LOG_FILE"; }
err()  { echo -e "${RED}[$(date '+%H:%M:%S')] [ERROR]${NC} $*" | tee -a "$LOG_FILE" >&2; }

cleanup() {
    if [[ $? -ne 0 ]]; then
        err "Skrypt zakończył się błędem. Sprawdź log: ${LOG_FILE}"
        err "Backup konfiguracji dostępny w: ${BACKUP_VERSIONED}"
    fi
}
trap cleanup EXIT

# --- Pobranie listy serwisów z docker-compose.yml ---
get_services() {
    docker compose -f "$COMPOSE_FILE" config --services 2>/dev/null
}

# --- Sprawdzenie wymagań ---
preflight_checks() {
    log "Sprawdzanie wymagań wstępnych..."

    if [[ $EUID -ne 0 ]]; then
        err "Skrypt musi być uruchomiony jako root."
        exit 1
    fi

    if ! command -v docker &>/dev/null; then
        err "Docker nie jest zainstalowany."
        exit 1
    fi

    if ! docker info &>/dev/null; then
        err "Demon Docker nie działa."
        exit 1
    fi

    if ! docker compose version &>/dev/null; then
        err "Docker Compose (plugin) nie jest dostępny."
        exit 1
    fi

    if [[ ! -f "$COMPOSE_FILE" ]]; then
        err "Brak pliku ${COMPOSE_FILE}"
        exit 1
    fi

    if ! curl -sf --max-time 5 https://hub.docker.com >/dev/null 2>&1; then
        warn "Brak połączenia z Docker Hub — pull może się nie powieść."
    fi

    local available_kb
    available_kb=$(df "$WORKDIR" --output=avail | tail -1 | tr -d ' ')
    if [[ "$available_kb" -lt 2097152 ]]; then
        warn "Mało wolnego miejsca na dysku (< 2GB). Aktualizacja może się nie powieść."
    fi

    log "Wymagania wstępne spełnione."
}

# --- Backup ---
create_backup() {
    log "Tworzenie backupu konfiguracji -> ${BACKUP_VERSIONED}"
    mkdir -p "$BACKUP_VERSIONED"

    local missing=0
    for file in "${CONFIG_FILES[@]}"; do
        if [[ -f "${WORKDIR}/${file}" ]]; then
            cp -f "${WORKDIR}/${file}" "${BACKUP_VERSIONED}/"
        else
            warn "Plik konfiguracyjny nie istnieje: ${file}"
            ((missing++))
        fi
    done

    # Backup aktualnych wersji obrazów
    docker compose -f "$COMPOSE_FILE" ps --format '{{.Name}} {{.Image}}' \
        > "${BACKUP_VERSIONED}/image_versions_before.txt" 2>/dev/null || true

    # Backup wolumenów Zitadel/CockroachDB (dump nazw)
    docker volume ls --format '{{.Name}}' | grep -iE 'zitadel|cockroach|netbird' \
        > "${BACKUP_VERSIONED}/volumes_list.txt" 2>/dev/null || true

    if [[ $missing -gt 0 ]]; then
        warn "Brakuje ${missing} plików konfiguracyjnych w backupie."
    fi

    # Rotacja starych backupów (zachowaj ostatnie 10)
    local count
    count=$(find "$BACKUP_DIR" -maxdepth 1 -mindepth 1 -type d | wc -l)
    if [[ "$count" -gt 10 ]]; then
        log "Rotacja backupów — usuwanie najstarszych (zachowano 10)..."
        find "$BACKUP_DIR" -maxdepth 1 -mindepth 1 -type d \
            | sort | head -n -10 | xargs rm -rf
    fi

    log "Backup zakończony."
}

# --- Zapis stanu kontenerów przed aktualizacją ---
save_pre_state() {
    log "Zapisywanie stanu kontenerów przed aktualizacją..."
    docker compose -f "$COMPOSE_FILE" ps >> "$LOG_FILE" 2>&1 || true
}

# --- Pull wszystkich obrazów ---
pull_images() {
    log "Pobieranie nowych obrazów dla WSZYSTKICH serwisów..."

    local retries=3
    local attempt=1

    while [[ $attempt -le $retries ]]; do
        if docker compose -f "$COMPOSE_FILE" pull 2>&1 | tee -a "$LOG_FILE"; then
            log "Wszystkie obrazy pobrane pomyślnie."
            return 0
        fi
        warn "Pull nie powiódł się (próba ${attempt}/${retries}). Ponawiam za 10s..."
        sleep 10
        ((attempt++))
    done

    err "Nie udało się pobrać obrazów po ${retries} próbach."
    exit 1
}

# --- Restart wszystkich serwisów ---
recreate_services() {
    log "Restartowanie WSZYSTKICH serwisów (force-recreate)..."

    if ! docker compose -f "$COMPOSE_FILE" up -d --force-recreate 2>&1 | tee -a "$LOG_FILE"; then
        err "Nie udało się uruchomić serwisów."
        return 1
    fi

    log "Kontenery uruchomione."
}

# --- Healthcheck ---
healthcheck() {
    log "Sprawdzanie stanu serwisów (timeout: ${HEALTHCHECK_TIMEOUT}s)..."

    local elapsed=0
    local all_healthy
    local services
    mapfile -t services < <(get_services)

    log "Monitorowane serwisy (${#services[@]}): ${services[*]}"

    while [[ $elapsed -lt $HEALTHCHECK_TIMEOUT ]]; do
        all_healthy=true

        for svc in "${services[@]}"; do
            local status
            status=$(docker compose -f "$COMPOSE_FILE" ps --format '{{.State}}' "$svc" 2>/dev/null || echo "missing")

            if [[ "$status" != "running" ]]; then
                all_healthy=false
                break
            fi
        done

        if $all_healthy; then
            log "Wszystkie serwisy (${#services[@]}) działają poprawnie."
            return 0
        fi

        sleep "$HEALTHCHECK_INTERVAL"
        ((elapsed += HEALTHCHECK_INTERVAL))
    done

    err "Nie wszystkie serwisy uruchomiły się w ciągu ${HEALTHCHECK_TIMEOUT}s."
    warn "Status kontenerów:"
    docker compose -f "$COMPOSE_FILE" ps 2>&1 | tee -a "$LOG_FILE"

    for svc in "${services[@]}"; do
        local state
        state=$(docker compose -f "$COMPOSE_FILE" ps --format '{{.State}}' "$svc" 2>/dev/null || echo "unknown")
        if [[ "$state" != "running" ]]; then
            err "Logi serwisu ${svc} (ostatnie 50 linii):"
            docker compose -f "$COMPOSE_FILE" logs --tail=50 "$svc" 2>&1 | tee -a "$LOG_FILE"
        fi
    done

    return 1
}

# --- Rollback ---
rollback() {
    warn "Rozpoczynam rollback do poprzedniej konfiguracji..."

    for file in "${CONFIG_FILES[@]}"; do
        if [[ -f "${BACKUP_VERSIONED}/${file}" ]]; then
            cp -f "${BACKUP_VERSIONED}/${file}" "${WORKDIR}/"
        fi
    done

    docker compose -f "$COMPOSE_FILE" up -d --force-recreate 2>&1 | tee -a "$LOG_FILE"
    log "Rollback zakończony. Sprawdź ręcznie stan serwisów."
}

# --- Czyszczenie starych obrazów ---
cleanup_images() {
    log "Usuwanie nieużywanych obrazów Docker..."
    docker image prune -f 2>&1 | tee -a "$LOG_FILE" || true
}

# --- Podsumowanie ---
summary() {
    log "=== PODSUMOWANIE AKTUALIZACJI ==="
    log "Czas: $(date)"
    log "Backup: ${BACKUP_VERSIONED}"
    log "Log: ${LOG_FILE}"
    log "Aktualne wersje obrazów:"
    docker compose -f "$COMPOSE_FILE" ps --format 'table {{.Name}}\t{{.Image}}\t{{.Status}}' 2>&1 | tee -a "$LOG_FILE"

    # Porównanie wersji przed/po
    if [[ -f "${BACKUP_VERSIONED}/image_versions_before.txt" ]]; then
        log "Zmiany obrazów:"
        local before after
        before="${BACKUP_VERSIONED}/image_versions_before.txt"
        after=$(docker compose -f "$COMPOSE_FILE" ps --format '{{.Name}} {{.Image}}' 2>/dev/null)
        diff <(sort "$before") <(echo "$after" | sort) 2>/dev/null | tee -a "$LOG_FILE" || log "Brak zmian w wersjach obrazów."
    fi

    log "================================="
}

# --- MAIN ---
main() {
    log "=== Rozpoczęcie aktualizacji NetBird (WSZYSTKIE SERWISY) ==="

    preflight_checks
    create_backup
    save_pre_state
    pull_images
    recreate_services

    if ! healthcheck; then
        err "Healthcheck nie powiódł się."
        read -r -t 30 -p "Czy wykonać rollback? [t/N]: " answer </dev/tty || answer="N"
        if [[ "${answer,,}" == "t" ]]; then
            rollback
        else
            warn "Rollback pominięty. Sprawdź ręcznie."
        fi
    fi

    cleanup_images
    summary

    log "=== Aktualizacja zakończona ==="
}

main "$@"

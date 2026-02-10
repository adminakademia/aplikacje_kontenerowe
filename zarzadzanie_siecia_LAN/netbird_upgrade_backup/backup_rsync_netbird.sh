#!/bin/bash
# Skrypt realizujacy kopie zapasowa samodzielnie utrzymywanego NetBird 
# z wykorzystaniem rsync na inny Linux
# ------------------------------------------------


# --- Konfiguracja ---
BACKUP_SERVER="user@1.1.1.1"     # Wpisz adres serwera na który będzie wysyłany backup
BACKUP_PATH="/backup/vm-netbird" # Wpisz ścieżkę do katalogu do którym będzie wysyłana kopia zapasowa na zdalnym serwerze
SSH_KEY="/root/.ssh/backup_key"  # Wpisz ścieżkę do klucza prywatnego SSH jaki ma być wykorzystany do uwierzytelnienia ze zdalnym serwerem do którego będzie wysyłana kopia zapasowa
WORKDIR="/netbird"   # Wpisz ścieżkę katalogu w którym masz pliki zawierające: docker-compose.yml, Caddyfile, dashboard.env, relay.env,
#                   management.json, turnserver.conf, zitadel.env, zdb.env,
#                   machinekey/
LOG_FILE="/var/log/backup-rsync.log"
DATE=$(date '+%Y-%m-%d %H:%M:%S')

# Katalogi do backupu
DIRS_TO_BACKUP=(
    "$WORKDIR"
    "/var/lib/docker/volumes"
)

# Opcje rsync
RSYNC_OPTS="-avz --delete --delete-excluded --exclude='*.tmp' --exclude='*.cache'"

# Funkcja logowania
log() {
    echo "[$DATE] $1" | tee -a "$LOG_FILE"
}

# Start backupu
log "=== Rozpoczęcie kopii zapasowej ==="

# Sprawdź połączenie SSH
if ! ssh -i "$SSH_KEY" -o ConnectTimeout=10 "$BACKUP_SERVER" "exit" 2>/dev/null; then
    log "BŁĄD: Nie można połączyć się z serwerem backup"
    exit 1
fi

# Wykonaj backup każdego katalogu
for DIR in "${DIRS_TO_BACKUP[@]}"; do
    if [ ! -d "$DIR" ]; then
        log "OSTRZEŻENIE: Katalog $DIR nie istnieje, pomijam"
        continue
    fi

    log "Kopiowanie: $DIR"

    # Utwórz odpowiednią strukturę katalogów na serwerze docelowym
    REMOTE_DIR="$BACKUP_PATH$(dirname $DIR)"
    ssh -i "$SSH_KEY" "$BACKUP_SERVER" "mkdir -p $REMOTE_DIR"

    # Wykonaj rsync
    if rsync $RSYNC_OPTS -e "ssh -i $SSH_KEY" "$DIR" "$BACKUP_SERVER:$BACKUP_PATH$(dirname $DIR)/"; then
        log "Sukces: $DIR skopiowany"
    else
        log "BŁĄD: Nie udało się skopiować $DIR"
        exit 1
    fi
done

log "=== Kopia zapasowa zakończona pomyślnie ==="


exit 0


#!/bin/sh
# CGI: load_incident_state.sh
# Returns incident sidecar state files from /playbooks/incident-state as JSON array.

STATE_DIR="/playbooks/incident-state"
. "/var/www/localhost/cgi-bin/_log.sh"

echo "Content-Type: application/json"
echo "Access-Control-Allow-Origin: *"
echo ""

if [ ! -d "$STATE_DIR" ] || [ -z "$(find "$STATE_DIR" -maxdepth 1 -name '*.json' 2>/dev/null | head -1)" ]; then
    echo "[]"
    exit 0
fi

echo "["
FIRST=1
for FILE in $(find "$STATE_DIR" -maxdepth 1 -name '*.json' | sort); do
    [ -f "$FILE" ] || continue
    if ! jq -e . "$FILE" >/dev/null 2>&1; then
        log_event "warn" "incident_state_load" "$FILE" "skipped_invalid_json"
        continue
    fi
    if [ $FIRST -eq 1 ]; then
        FIRST=0
    else
        echo ","
    fi
    cat "$FILE"
done
echo "]"

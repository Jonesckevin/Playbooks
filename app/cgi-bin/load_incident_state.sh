#!/bin/sh
# CGI: load_incident_state.sh
# Returns incident sidecar state files from /playbooks/incident-state as JSON array.

STATE_DIR="/playbooks/incident-state"

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
    if [ $FIRST -eq 1 ]; then
        FIRST=0
    else
        echo ","
    fi
    cat "$FILE"
done
echo "]"

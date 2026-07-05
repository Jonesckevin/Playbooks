#!/bin/sh
# CGI: save_playbook.sh
# Reads a JSON POST body, validates required fields,
# writes it to /var/www/localhost/htdocs/playbooks-custom/<uuid>.json on the Docker volume.

PLAYBOOKS_DIR="/var/www/localhost/htdocs/playbooks-custom"
. "/var/www/localhost/cgi-bin/_log.sh"

# Function to send a JSON error response
send_error() {
    HTTP_STATUS=$1
    ERROR_MESSAGE=$2
    echo "Status: $HTTP_STATUS"
    echo "Content-Type: application/json"
    echo "Access-Control-Allow-Origin: *"
    echo ""
    echo "{\"ok\": false, \"error\": \"$ERROR_MESSAGE\"}"
    exit 0
}

# Only accept POST
if [ "$REQUEST_METHOD" != "POST" ]; then
    send_error 405 "Method not allowed"
fi

# Read the POST body (Content-Length bytes)
BODY=""
if [ -n "$CONTENT_LENGTH" ] && [ "$CONTENT_LENGTH" -gt 0 ]; then
    BODY=$(dd bs=1 count="$CONTENT_LENGTH" 2>/dev/null)
fi

if [ -z "$BODY" ]; then
    send_error 400 "Empty body"
fi

# Basic validation - check 'name' field is present and non-empty
NAME=$(echo "$BODY" | grep -o '"name":"[^"]*"' | head -1 | sed 's/"name":"//;s/"//')
if [ -z "$NAME" ]; then
    send_error 400 "Missing required field: name"
fi

# Generate a unique ID using timestamp + random
TIMESTAMP=$(date +%s%N 2>/dev/null || date +%s)
RAND=$(cat /dev/urandom | tr -dc 'a-f0-9' | head -c 8)
UUID="${TIMESTAMP}-${RAND}"

# Ensure storage directory exists
mkdir -p "$PLAYBOOKS_DIR"

# Inject the server-generated id, num, and createdAt into the JSON
# Count existing playbooks to assign num
NUM=$(ls "$PLAYBOOKS_DIR"/*.json 2>/dev/null | wc -l)
NUM=$((NUM + 1))
CREATED=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# Strip any trailing } and append our server fields
BODY_STRIPPED=$(echo "$BODY" | sed 's/}[[:space:]]*$//')
FINAL="${BODY_STRIPPED},\"id\":\"${UUID}\",\"num\":${NUM},\"createdAt\":\"${CREATED}\",\"source\":\"custom\"}"

# Write to temp file first, then move for atomicity
TMP_FILE="${PLAYBOOKS_DIR}/${UUID}.tmp"
echo "$FINAL" > "$TMP_FILE"

if [ $? -eq 0 ]; then
    mv "$TMP_FILE" "${PLAYBOOKS_DIR}/${UUID}.json"
    if [ $? -eq 0 ]; then
        log_event "info" "playbook_save" "$UUID" "created num=${NUM} source=custom"
        echo "Content-Type: application/json"
        echo "Access-Control-Allow-Origin: *"
        echo ""
        echo "{\"ok\":true,\"id\":\"${UUID}\",\"num\":${NUM}}"
    else
        rm -f "$TMP_FILE"
        log_event "error" "playbook_save" "$UUID" "finalize_failed"
        send_error 500 "Failed to finalize playbook file"
    fi
else
    log_event "error" "playbook_save" "$UUID" "temp_write_failed"
    send_error 500 "Failed to write temporary playbook file"
fi

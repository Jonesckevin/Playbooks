#!/bin/sh
# CGI: save_incident_state.sh
# Upserts incident sidecar JSON for a playbook at /playbooks/incident-state/<id>.json

STATE_DIR="/playbooks/incident-state"
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

if [ "$REQUEST_METHOD" != "POST" ]; then
    send_error 405 "Method not allowed"
fi

BODY=""
if [ -n "$CONTENT_LENGTH" ] && [ "$CONTENT_LENGTH" -gt 0 ]; then
    BODY=$(dd bs=1 count="$CONTENT_LENGTH" 2>/dev/null)
fi

if [ -z "$BODY" ]; then
    send_error 400 "Empty body"
fi

ID=$(echo "$BODY" | grep -o '"id":"[^"]*"' | head -1 | sed 's/"id":"//;s/"//')
ID=$(echo "$ID" | tr -cd 'a-zA-Z0-9._-')

if [ -z "$ID" ]; then
    send_error 400 "Missing required field: id"
fi

mkdir -p "$STATE_DIR"
TARGET="${STATE_DIR}/${ID}.json"
TMP_FILE="${TARGET}.tmp"

echo "$BODY" > "$TMP_FILE"
if [ $? -ne 0 ]; then
    log_event "error" "incident_state_save" "$ID" "temp_write_failed"
    send_error 500 "Failed to write temporary incident state"
fi

mv "$TMP_FILE" "$TARGET"
if [ $? -ne 0 ]; then
    rm -f "$TMP_FILE"
    log_event "error" "incident_state_save" "$ID" "finalize_failed"
    send_error 500 "Failed to save incident state"
fi

log_event "info" "incident_state_save" "$ID" "updated=true"
echo "Content-Type: application/json"
echo "Access-Control-Allow-Origin: *"
echo ""
echo "{\"ok\":true,\"id\":\"${ID}\"}"

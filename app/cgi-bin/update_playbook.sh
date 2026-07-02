#!/bin/sh
# CGI: update_playbook.sh
# Updates an existing playbook.
# - If custom exists (/playbooks/<id>.json), overwrite it.
# - Else write library override to /playbooks/library-overrides/<id>.json.

PLAYBOOKS_DIR="/playbooks"
OVERRIDE_DIR="${PLAYBOOKS_DIR}/library-overrides"
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

mkdir -p "$PLAYBOOKS_DIR"
mkdir -p "$OVERRIDE_DIR"

CUSTOM_TARGET="${PLAYBOOKS_DIR}/${ID}.json"
OVERRIDE_TARGET="${OVERRIDE_DIR}/${ID}.json"

TARGET="$OVERRIDE_TARGET"
SOURCE="library-override"
if [ -f "$CUSTOM_TARGET" ]; then
    TARGET="$CUSTOM_TARGET"
    SOURCE="custom"
fi

TMP_FILE="${TARGET}.tmp"
echo "$BODY" > "$TMP_FILE"
if [ $? -ne 0 ]; then
    log_event "error" "playbook_update" "$ID" "temp_write_failed target=${TARGET}"
    send_error 500 "Failed to write temporary update file"
fi

mv "$TMP_FILE" "$TARGET"
if [ $? -ne 0 ]; then
    rm -f "$TMP_FILE"
    log_event "error" "playbook_update" "$ID" "finalize_failed target=${TARGET}"
    send_error 500 "Failed to finalize playbook update"
fi

log_event "info" "playbook_update" "$ID" "source=${SOURCE} target=${TARGET}"
echo "Content-Type: application/json"
echo "Access-Control-Allow-Origin: *"
echo ""
echo "{\"ok\":true,\"id\":\"${ID}\",\"source\":\"${SOURCE}\"}"

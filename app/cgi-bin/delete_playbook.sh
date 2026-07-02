#!/bin/sh
# CGI: delete_playbook.sh
# Expects DELETE request with ?id=<uuid> query string.
# Removes the matching /playbooks/<uuid>.json file.

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

if [ "$REQUEST_METHOD" != "DELETE" ] && [ "$REQUEST_METHOD" != "POST" ]; then
    send_error 405 "Method not allowed"
fi

# Parse id from query string or POST body
if [ "$REQUEST_METHOD" = "POST" ]; then
    BODY=$(dd bs=1 count="${CONTENT_LENGTH:-0}" 2>/dev/null)
    ID=$(echo "$BODY" | grep -o '"id":"[^"]*"' | head -1 | sed 's/"id":"//;s/"//')
else
    ID=$(echo "$QUERY_STRING" | grep -o 'id=[^&]*' | sed 's/id=//')
fi

# Sanitise - allow alphanumeric IDs used by both custom and library playbooks.
ID=$(echo "$ID" | tr -cd 'a-zA-Z0-9._-')

if [ -z "$ID" ]; then
    send_error 400 "Missing id parameter"
fi

TARGET_CUSTOM="${PLAYBOOKS_DIR}/${ID}.json"
TARGET_OVERRIDE="${OVERRIDE_DIR}/${ID}.json"

if [ -f "$TARGET_CUSTOM" ]; then
    rm "$TARGET_CUSTOM"
    if [ $? -eq 0 ]; then
        log_event "info" "playbook_delete" "$ID" "source=custom"
        echo "Content-Type: application/json"
        echo "Access-Control-Allow-Origin: *"
        echo ""
        echo "{\"ok\":true,\"deleted\":\"${ID}\",\"source\":\"custom\"}"
    else
        log_event "error" "playbook_delete" "$ID" "delete_failed source=custom"
        send_error 500 "Failed to delete custom playbook"
    fi
    exit 0
fi

if [ -f "$TARGET_OVERRIDE" ]; then
    rm "$TARGET_OVERRIDE"
    if [ $? -eq 0 ]; then
        log_event "info" "playbook_delete" "$ID" "source=library-override reverted=true"
        echo "Content-Type: application/json"
        echo "Access-Control-Allow-Origin: *"
        echo ""
        echo "{\"ok\":true,\"deleted\":\"${ID}\",\"source\":\"library-override\",\"reverted\":true}"
    else
        log_event "error" "playbook_delete" "$ID" "delete_failed source=library-override"
        send_error 500 "Failed to remove library override"
    fi
    exit 0
fi

log_event "warn" "playbook_delete" "$ID" "not_found"
send_error 404 "Playbook not found"


#!/bin/sh
# CGI: delete_playbook.sh
# Expects DELETE request with ?id=<uuid> query string.
# Removes the matching /playbooks/<uuid>.json file.

PLAYBOOKS_DIR="/playbooks"
OVERRIDE_DIR="${PLAYBOOKS_DIR}/library-overrides"

echo "Content-Type: application/json"
echo "Access-Control-Allow-Origin: *"
echo ""

if [ "$REQUEST_METHOD" != "DELETE" ] && [ "$REQUEST_METHOD" != "POST" ]; then
    echo '{"error":"Method not allowed"}'
    exit 0
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
    echo '{"error":"Missing id parameter"}'
    exit 0
fi

TARGET_CUSTOM="${PLAYBOOKS_DIR}/${ID}.json"
TARGET_OVERRIDE="${OVERRIDE_DIR}/${ID}.json"

if [ -f "$TARGET_CUSTOM" ]; then
    rm "$TARGET_CUSTOM"
    if [ $? -eq 0 ]; then
        echo "{\"ok\":true,\"deleted\":\"${ID}\",\"source\":\"custom\"}"
    else
        echo '{"error":"Failed to delete custom playbook"}'
    fi
    exit 0
fi

if [ -f "$TARGET_OVERRIDE" ]; then
    rm "$TARGET_OVERRIDE"
    if [ $? -eq 0 ]; then
        echo "{\"ok\":true,\"deleted\":\"${ID}\",\"source\":\"library-override\",\"reverted\":true}"
    else
        echo '{"error":"Failed to remove library override"}'
    fi
    exit 0
fi

echo '{"error":"Playbook not found"}'
exit 0

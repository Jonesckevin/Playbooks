#!/bin/sh
# CGI: delete_playbook.sh
# Expects DELETE request with ?id=<uuid> query string.
# Removes the matching /playbooks/<uuid>.json file.

PLAYBOOKS_DIR="/playbooks"

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

# Sanitise - only allow safe characters (timestamp-hex pattern)
ID=$(echo "$ID" | tr -cd '0-9a-f-')

if [ -z "$ID" ]; then
    echo '{"error":"Missing id parameter"}'
    exit 0
fi

TARGET="${PLAYBOOKS_DIR}/${ID}.json"

if [ ! -f "$TARGET" ]; then
    echo '{"error":"Playbook not found"}'
    exit 0
fi

rm "$TARGET"
if [ $? -eq 0 ]; then
    echo "{\"ok\":true,\"deleted\":\"${ID}\"}"
else
    echo '{"error":"Failed to delete playbook"}'
fi

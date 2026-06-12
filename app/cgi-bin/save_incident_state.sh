#!/bin/sh
# CGI: save_incident_state.sh
# Upserts incident sidecar JSON for a playbook at /playbooks/incident-state/<id>.json

STATE_DIR="/playbooks/incident-state"

echo "Content-Type: application/json"
echo "Access-Control-Allow-Origin: *"
echo ""

if [ "$REQUEST_METHOD" != "POST" ]; then
    echo '{"error":"Method not allowed"}'
    exit 0
fi

BODY=""
if [ -n "$CONTENT_LENGTH" ] && [ "$CONTENT_LENGTH" -gt 0 ]; then
    BODY=$(dd bs=1 count="$CONTENT_LENGTH" 2>/dev/null)
fi

if [ -z "$BODY" ]; then
    echo '{"error":"Empty body"}'
    exit 0
fi

ID=$(echo "$BODY" | grep -o '"id":"[^"]*"' | head -1 | sed 's/"id":"//;s/"//')
ID=$(echo "$ID" | tr -cd 'a-zA-Z0-9._-')

if [ -z "$ID" ]; then
    echo '{"error":"Missing required field: id"}'
    exit 0
fi

mkdir -p "$STATE_DIR"
TARGET="${STATE_DIR}/${ID}.json"

echo "$BODY" > "$TARGET"
if [ $? -ne 0 ]; then
    echo '{"error":"Failed to save incident state"}'
    exit 0
fi

echo "{\"ok\":true,\"id\":\"${ID}\"}"

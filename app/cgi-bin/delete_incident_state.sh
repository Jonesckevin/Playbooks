#!/bin/sh
# CGI: delete_incident_state.sh
# Deletes incident sidecar state file /playbooks/incident-state/<id>.json

STATE_DIR="/playbooks/incident-state"

echo "Content-Type: application/json"
echo "Access-Control-Allow-Origin: *"
echo ""

if [ "$REQUEST_METHOD" != "DELETE" ]; then
    echo '{"error":"Method not allowed"}'
    exit 0
fi

ID=$(echo "$QUERY_STRING" | sed -n 's/.*id=\([^&]*\).*/\1/p')
ID=$(printf "%s" "$ID" | tr -cd 'a-zA-Z0-9._-')

if [ -z "$ID" ]; then
    echo '{"error":"Missing required query parameter: id"}'
    exit 0
fi

TARGET="${STATE_DIR}/${ID}.json"
if [ -f "$TARGET" ]; then
    rm -f "$TARGET"
fi

echo "{\"ok\":true,\"id\":\"${ID}\"}"

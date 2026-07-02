#!/bin/sh
# CGI: delete_incident_state.sh
# Deletes incident sidecar state file /playbooks/incident-state/<id>.json

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

if [ "$REQUEST_METHOD" != "DELETE" ]; then
    send_error 405 "Method not allowed"
fi

ID=$(echo "$QUERY_STRING" | sed -n 's/.*id=\([^&]*\).*/\1/p')
ID=$(printf "%s" "$ID" | tr -cd 'a-zA-Z0-9._-')

if [ -z "$ID" ]; then
    send_error 400 "Missing required query parameter: id"
fi

TARGET="${STATE_DIR}/${ID}.json"
if [ -f "$TARGET" ]; then
    rm -f "$TARGET"
    if [ $? -ne 0 ]; then
        log_event "error" "incident_state_delete" "$ID" "delete_failed"
        send_error 500 "Failed to delete incident state file"
    fi
fi

# Always return success, even if file didn't exist (idempotent)
log_event "info" "incident_state_delete" "$ID" "deleted=true"
echo "Content-Type: application/json"
echo "Access-Control-Allow-Origin: *"
echo ""
echo "{\"ok\":true,\"id\":\"${ID}\"}"

#!/bin/sh
# CGI: save_playbook.sh
# Reads a JSON POST body, validates required fields,
# writes it to /playbooks/<uuid>.json on the Docker volume.

PLAYBOOKS_DIR="/playbooks"

# ── CGI headers ────────────────────────────────────────────────────────────
echo "Content-Type: application/json"
echo "Access-Control-Allow-Origin: *"
echo ""

# Only accept POST
if [ "$REQUEST_METHOD" != "POST" ]; then
    echo '{"error":"Method not allowed"}'
    exit 0
fi

# Read the POST body (Content-Length bytes)
BODY=""
if [ -n "$CONTENT_LENGTH" ] && [ "$CONTENT_LENGTH" -gt 0 ]; then
    BODY=$(dd bs=1 count="$CONTENT_LENGTH" 2>/dev/null)
fi

if [ -z "$BODY" ]; then
    echo '{"error":"Empty body"}'
    exit 0
fi

# Basic validation - check 'name' field is present and non-empty
NAME=$(echo "$BODY" | grep -o '"name":"[^"]*"' | head -1 | sed 's/"name":"//;s/"//')
if [ -z "$NAME" ]; then
    echo '{"error":"Missing required field: name"}'
    exit 0
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

# Write to volume
echo "$FINAL" > "${PLAYBOOKS_DIR}/${UUID}.json"

if [ $? -eq 0 ]; then
    echo "{\"ok\":true,\"id\":\"${UUID}\",\"num\":${NUM}}"
else
    echo '{"error":"Failed to write playbook file"}'
fi

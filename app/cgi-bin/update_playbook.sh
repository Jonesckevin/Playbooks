#!/bin/sh
# CGI: update_playbook.sh
# Updates an existing playbook.
# - If custom exists (/playbooks/<id>.json), overwrite it.
# - Else write library override to /playbooks/library-overrides/<id>.json.

PLAYBOOKS_DIR="/playbooks"
OVERRIDE_DIR="${PLAYBOOKS_DIR}/library-overrides"

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

echo "$BODY" > "$TARGET"
if [ $? -ne 0 ]; then
    echo '{"error":"Failed to update playbook"}'
    exit 0
fi

echo "{\"ok\":true,\"id\":\"${ID}\",\"source\":\"${SOURCE}\"}"

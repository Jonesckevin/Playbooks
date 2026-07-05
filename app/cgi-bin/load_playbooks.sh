#!/bin/sh
# CGI: load_playbooks.sh
# Reads all .json files from /var/www/localhost/htdocs/playbooks-custom volume and returns them as a JSON array.

# ── Security: Restrict CORS to allowed origins ────────────────────────
ORIGIN="${HTTP_ORIGIN:-}"

# Only allow requests from known origins
if [ -n "$ORIGIN" ]; then
    case "$ORIGIN" in
        http://localhost:9020|http://localhost:8080|http://localhost)
            # Allowed origin
            ;;
        *)
            # Blocked origin - return empty response
            echo "Content-Type: application/json"
            echo ""
            echo '[]'
            exit 0
            ;;
    esac
fi

PLAYBOOKS_DIR="/var/www/localhost/htdocs/playbooks-custom"
. "/var/www/localhost/cgi-bin/_log.sh"

echo "Content-Type: application/json"
# Only echo origin if it's whitelisted
if [ -n "$ORIGIN" ] && echo "$ALLOWED_ORIGINS" | grep -q "^$ORIGIN$"; then
    echo "Access-Control-Allow-Origin: $ORIGIN"
fi
echo ""

# ── Safety checks ──────────────────────────────────────────────────────
if [ ! -d "$PLAYBOOKS_DIR" ] || [ ! -r "$PLAYBOOKS_DIR" ]; then
    echo "[]"
    exit 0
fi

# Concatenate all JSON files into a valid array
echo "["
FIRST=1
for FILE in $(find "$PLAYBOOKS_DIR" -maxdepth 2 -name '*.json' | sort); do
    [ -f "$FILE" ] || continue
    if ! jq -e . "$FILE" >/dev/null 2>&1; then
        log_event "warn" "playbook_load" "$FILE" "skipped_invalid_json"
        continue
    fi
    if [ $FIRST -eq 1 ]; then
        FIRST=0
    else
        echo ","
    fi
    cat "$FILE"
done
echo "]"

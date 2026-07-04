#!/bin/sh
# CGI: list_override_playbooks.sh
# Scans the /var/www/localhost/htdocs/playbooks/ directory and returns
# a list of override playbooks with metadata for frontend discovery.

PLAYBOOKS_OVERRIDE_DIR="/var/www/localhost/htdocs/playbooks"

echo "Content-Type: application/json"
echo "Access-Control-Allow-Origin: *"
echo ""

# If no playbooks directory or no files, return empty array
if [ ! -d "$PLAYBOOKS_OVERRIDE_DIR" ] || [ -z "$(find "$PLAYBOOKS_OVERRIDE_DIR" -maxdepth 3 -name '*.json' 2>/dev/null | head -1)" ]; then
    echo "[]"
    exit 0
fi

# Build a JSON array of override playbook metadata
{
    echo "["
    FIRST=1
    for FILE in $(find "$PLAYBOOKS_OVERRIDE_DIR" -name '*.json' | sort); do
        [ -f "$FILE" ] || continue
        
        # Validate JSON
        if ! jq -e . "$FILE" >/dev/null 2>&1; then
            continue
        fi
        
        # Extract relative path for display
        RELPATH=$(echo "$FILE" | sed "s|$PLAYBOOKS_OVERRIDE_DIR/||")
        
        # Read metadata from the JSON file using jq
        ID=$(jq -r '.id // empty' "$FILE")
        NAME=$(jq -r '.name // .title // empty' "$FILE")
        CATEGORY=$(jq -r '.cat // .category // empty' "$FILE")
        
        if [ -z "$ID" ] || [ -z "$NAME" ]; then
            continue
        fi
        
        if [ $FIRST -eq 1 ]; then
            FIRST=0
        else
            echo ","
        fi
        
        # Output metadata entry as JSON (using jq to properly escape values)
        jq -n \
            --arg id "$ID" \
            --arg name "$NAME" \
            --arg cat "$CATEGORY" \
            --arg file "$RELPATH" \
            '{id: $id, name: $name, cat: $cat, file: $file, override: true}'
    done
    echo "]"
}

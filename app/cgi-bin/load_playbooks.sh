#!/bin/sh
# CGI: load_playbooks.sh
# Reads all .json files from /playbooks/ volume and returns them as a JSON array.

PLAYBOOKS_DIR="/playbooks"

echo "Content-Type: application/json"
echo "Access-Control-Allow-Origin: *"
echo ""

# If no files exist, return empty array
if [ ! -d "$PLAYBOOKS_DIR" ] || [ -z "$(find "$PLAYBOOKS_DIR" -maxdepth 2 -name '*.json' 2>/dev/null | head -1)" ]; then
    echo "[]"
    exit 0
fi

# Concatenate all JSON files into a valid array
echo "["
FIRST=1
for FILE in $(find "$PLAYBOOKS_DIR" -maxdepth 2 -name '*.json' | sort); do
    [ -f "$FILE" ] || continue
    if [ $FIRST -eq 1 ]; then
        FIRST=0
    else
        echo ","
    fi
    cat "$FILE"
done
echo "]"

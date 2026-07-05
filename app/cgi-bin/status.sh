#!/bin/sh
# CGI: status.sh
# Returns runtime statistics about the application.

PLAYBOOKS_DIR="/var/www/localhost/htdocs/playbooks-custom"
INCIDENT_STATE_DIR="/var/www/localhost/htdocs/incident-state"

echo "Content-Type: application/json"
echo "Access-Control-Allow-Origin: *"
echo ""

# --- Playbook Count ---
playbook_count=$(ls -1 "${PLAYBOOKS_DIR}"/*.json 2>/dev/null | wc -l)

# --- Incident State Count ---
incident_state_count=$(ls -1 "${INCIDENT_STATE_DIR}"/*.json 2>/dev/null | wc -l)

# --- Disk Usage ---
# Get disk usage for the playbooks volume. du -sh returns size and path.
disk_usage=$(du -sh "$PLAYBOOKS_DIR" | awk '{print $1}')

# --- Uptime ---
# Get uptime from the system.
uptime_str=$(uptime | sed 's/.*up \([^,]*\), .*/\1/')

echo "{"
echo "  \"ok\": true,"
echo "  \"playbook_count\": ${playbook_count:-0},"
echo "  \"incident_state_count\": ${incident_state_count:-0},"
echo "  \"disk_usage\": \"${disk_usage:-0B}\","
echo "  \"uptime\": \"${uptime_str:-unknown}\""
echo "}"

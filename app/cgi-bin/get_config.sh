#!/bin/sh
# CGI: get_config.sh
# Returns the active tool/SIEM selection as JSON, driven by SIEM_TOOL_1..6 env vars.
# Defaults: security_onion, sysmon, osquery, velociraptor, elastic, carbon_black

echo "Content-Type: application/json"
echo "Access-Control-Allow-Origin: *"
echo ""

T1="${SIEM_TOOL_1:-security_onion}"
T2="${SIEM_TOOL_2:-sysmon}"
T3="${SIEM_TOOL_3:-osquery}"
T4="${SIEM_TOOL_4:-velociraptor}"
T5="${SIEM_TOOL_5:-elastic}"
T6="${SIEM_TOOL_6:-carbon_black}"

printf '{"tools":["%s","%s","%s","%s","%s","%s"]}' "$T1" "$T2" "$T3" "$T4" "$T5" "$T6"

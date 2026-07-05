#!/bin/sh

echo "Content-Type: application/json"
echo ""

# Check if the web server is responding on its internal port
if wget -q -S -O /dev/null http://localhost:8080/index.html 2>&1 | grep -q "HTTP/1.1 200 OK"; then
  http_ok="true"
else
  http_ok="false"
fi

# Check if the playbooks data volume is readable
if [ -r "/var/www/localhost/htdocs/playbooks-custom" ]; then
  playbooks_ok="true"
else
  playbooks_ok="false"
fi

# If all checks pass, return a healthy status. Otherwise, return unhealthy.
if [ "$http_ok" = "true" ] && [ "$playbooks_ok" = "true" ]; then
  echo "{\"ok\": true, \"http_status\": $http_ok, \"playbooks_readable\": $playbooks_ok}"
  exit 0
else
  echo "{\"ok\": false, \"http_status\": $http_ok, \"playbooks_readable\": $playbooks_ok}"
  # Exit with a non-zero status code to mark the container as unhealthy
  exit 1
fi

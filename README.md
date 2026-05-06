# SOC IR Playbook Library — Docker Deployment

Alpine + Apache serving the SOC Incident Response Playbook Library.
Custom playbooks created via the web form are persisted as JSON files
on a named Docker volume at `/playbooks` inside the container.

## What's in this version (v3.0)

- 36 fully expanded playbooks from the CPT IR Playbook document
- 122 Splunk queries across detection, containment, eradication, and recovery phases
- Full step detail: each step shows a title, explanatory context, and where
  applicable a ready-to-use Splunk search
- Analyst playbook creator — saves to the Docker volume, shared across all browsers
- Sidebar navigation with live search and category filtering
- DNS attack playbook (tunnelling, DGA/fast-flux, amplification, rebinding)
- Base alert procedure (intake → triage → decision → documentation)

## Stack

| Component    | Detail                                       |
|-------------|----------------------------------------------|
| Base image  | alpine:3.19                                  |
| Web server  | Apache httpd (apache2 package only)          |
| Backend     | Three Apache CGI shell scripts               |
| Persistence | Docker named volume → `/playbooks` in container |
| Port        | 8080                                         |
| Image size  | ~10–12 MB                                    |

## Project structure

```
soc-playbooks/
├── Dockerfile
├── docker-compose.yml
├── README.md
└── app/
    ├── index.html          ← SPA shell (structure + external refs)
    ├── style.css           ← all styles
    ├── app.js              ← all JavaScript (library data + UI logic)
    └── cgi-bin/
        ├── save_playbook.sh    ← POST: writes /playbooks/<id>.json
        ├── load_playbooks.sh   ← GET:  returns all playbooks as JSON array
        └── delete_playbook.sh  ← POST: removes /playbooks/<id>.json
```

## Quick start

```bash
docker compose up -d

# View logs
docker compose logs -f

# Stop (volume data preserved)
docker compose down
```

Access at: **http://localhost:8080**

## Volume management

```bash
# List saved custom playbooks
docker run --rm -v soc-playbooks_playbook-data:/playbooks alpine ls /playbooks

# Backup volume to current directory
docker run --rm \
  -v soc-playbooks_playbook-data:/playbooks:ro \
  -v $(pwd):/backup \
  alpine tar -czf /backup/playbooks-backup.tar.gz /playbooks

# Restore from backup
docker run --rm \
  -v soc-playbooks_playbook-data:/playbooks \
  -v $(pwd):/backup \
  alpine tar -xzf /backup/playbooks-backup.tar.gz -C /
```

## Update the app (no data loss)

```bash
# Replace index.html or CGI scripts, then rebuild
docker compose up -d --build
# The playbook-data volume is untouched — custom playbooks survive the rebuild
```

## Nginx reverse proxy integration

Add to your existing nginx config:

```nginx
location /playbooks/ {
    proxy_pass         http://soc-playbooks:8080/;
    proxy_set_header   Host $host;
    proxy_set_header   X-Real-IP $remote_addr;
    proxy_set_header   X-Forwarded-For $proxy_add_x_forwarded_for;
}
```

## Add to an existing Docker Compose stack (e.g. HOL stack)

```yaml
  soc-playbooks:
    build: ./soc-playbooks
    image: soc-playbooks:latest
    container_name: soc-playbooks
    restart: unless-stopped
    volumes:
      - playbook-data:/playbooks
    networks:
      - your_existing_network   # share with nginx proxy

volumes:
  playbook-data:
    driver: local
```

## Air-gapped deployment

```bash
# Export on internet-connected host
docker save soc-playbooks:latest | gzip > soc-playbooks-v3.tar.gz

# On the air-gapped host
docker load < soc-playbooks-v3.tar.gz
docker compose up -d
```

## Migrating to Gitea (future)

This container uses Apache CGI for persistence. If you move to a locally
hosted Gitea instance, the three CGI functions in index.html are replaced
with Gitea Contents API calls — see the project documentation for the
migration guide.

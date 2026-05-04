# SOC IR Playbook Library — Docker Deployment

Alpine + Apache with CGI-based persistence. Custom playbooks analysts create
via the web form are saved as JSON files on a named Docker volume at
`/playbooks` inside the container. They survive container restarts and
rebuilds.

## Stack

| Component      | Detail                                      |
|---------------|----------------------------------------------|
| Base image     | alpine:3.19                                 |
| Web server     | Apache httpd (apache2 package)              |
| Persistence    | Docker named volume → `/playbooks` in container |
| Backend        | Apache CGI shell scripts (no Python/Node)   |
| Port           | 8080                                        |
| Image size     | ~10–12 MB                                   |

## Project structure

```
soc-playbooks/
├── Dockerfile
├── docker-compose.yml
├── index.html              ← full SPA playbook library
├── cgi-bin/
│   ├── save_playbook.sh    ← POST handler, writes /playbooks/<id>.json
│   ├── load_playbooks.sh   ← GET handler, returns all playbooks as JSON array
│   └── delete_playbook.sh  ← POST handler, removes /playbooks/<id>.json
└── README.md
```

## Quick start

```bash
# Build and run (detached)
docker compose up -d

# View live logs
docker compose logs -f

# Stop (volume data is preserved)
docker compose down
```

Access at: **http://localhost:8080**

---

## How persistence works

Each custom playbook saved via the web form is POSTed to
`/cgi-bin/save_playbook.sh`, which writes it as an individual JSON file:

```
/playbooks/
  1748000000000-a3f2bc91.json
  1748000000123-d91fe820.json
  ...
```

The named volume `playbook-data` is mounted at `/playbooks` so data
persists across container restarts, upgrades, and rebuilds.

On page load, `/cgi-bin/load_playbooks.sh` reads all files and returns
them as a JSON array — the browser merges them into the library view.

---

## Volume management

```bash
# List volume contents
docker run --rm -v soc-playbooks_playbook-data:/playbooks alpine ls /playbooks

# Backup the volume
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

---

## Updating the app (rebuild without losing data)

```bash
# Replace index.html or CGI scripts, then:
docker compose up -d --build
# Volume data is untouched — only the image layers are rebuilt
```

---

## Reverse proxy integration (nginx)

Add to your existing nginx config:

```nginx
location /playbooks/ {
    proxy_pass         http://soc-playbooks:8080/;
    proxy_set_header   Host $host;
    proxy_set_header   X-Real-IP $remote_addr;
}
```

To add this container to your existing HOL Compose stack, append:

```yaml
  soc-playbooks:
    build: ./soc-playbooks
    image: soc-playbooks:latest
    container_name: soc-playbooks
    restart: unless-stopped
    volumes:
      - playbook-data:/playbooks
    networks:
      - your_existing_network   # share nginx's network

volumes:
  playbook-data:
    driver: local
```

---

## Air-gapped deployment

```bash
# Export on internet-connected host
docker save soc-playbooks:latest | gzip > soc-playbooks.tar.gz

# Copy to air-gapped host, then:
docker load < soc-playbooks.tar.gz
docker compose up -d
```

FROM node:22-alpine AS navigator-builder

RUN apk add --no-cache git
WORKDIR /build
RUN git clone --depth 1 https://github.com/mitre-attack/attack-navigator.git
WORKDIR /build/attack-navigator/nav-app
RUN npm install
RUN npm run build -- --configuration production --base-href /attack-navigator/ --deploy-url /attack-navigator/

FROM alpine:3.19

# ── Install Apache, Python, jq, and wget for healthchecks ──────────────────
RUN apk add --no-cache apache2 python3 bash jq wget

# ── Enable mod_cgi ────────────────────────────────────────────────────────
RUN sed -i 's/#LoadModule cgi_module/LoadModule cgi_module/' /etc/apache2/httpd.conf

# ── Listen on 8080, set server name, disable directory listing ────────────
RUN sed -i 's/^Listen 80$/Listen 8080/'                            /etc/apache2/httpd.conf && \
    sed -i 's/#ServerName www.example.com:80/ServerName localhost/' /etc/apache2/httpd.conf && \
    sed -i 's/Options Indexes FollowSymLinks/Options FollowSymLinks/' /etc/apache2/httpd.conf && \
    sed -i 's|/run/apache2/httpd.pid|/tmp/httpd.pid|g' /etc/apache2/httpd.conf /etc/apache2/conf.d/*.conf

# ── CGI directory config ──────────────────────────────────────────────────
RUN echo '<Directory "/var/www/localhost/cgi-bin">'              >> /etc/apache2/conf.d/cgi.conf && \
    echo '    AllowOverride None'                                 >> /etc/apache2/conf.d/cgi.conf && \
    echo '    Options +ExecCGI'                                   >> /etc/apache2/conf.d/cgi.conf && \
    echo '    AddHandler cgi-script .sh'                          >> /etc/apache2/conf.d/cgi.conf && \
    echo '    Require all granted'                                >> /etc/apache2/conf.d/cgi.conf && \
    echo '</Directory>'                                           >> /etc/apache2/conf.d/cgi.conf && \
    echo 'ScriptAlias /cgi-bin/ /var/www/localhost/cgi-bin/'     >> /etc/apache2/conf.d/cgi.conf && \
    echo 'PassEnv SIEM_TOOL_1 SIEM_TOOL_2 SIEM_TOOL_3 SIEM_TOOL_4 SIEM_TOOL_5 SIEM_TOOL_6' >> /etc/apache2/conf.d/cgi.conf && \
    echo '' >> /etc/apache2/conf.d/cgi.conf && \
    echo '# Security headers' >> /etc/apache2/conf.d/cgi.conf && \
    echo 'Header set X-Content-Type-Options: nosniff' >> /etc/apache2/conf.d/cgi.conf && \
    echo 'Header set X-Frame-Options: DENY' >> /etc/apache2/conf.d/cgi.conf && \
    echo 'Header set X-XSS-Protection: "1; mode=block"' >> /etc/apache2/conf.d/cgi.conf && \
    echo 'Header set Referrer-Policy: strict-origin-when-cross-origin' >> /etc/apache2/conf.d/cgi.conf

# ── Logs → stdout/stderr so docker logs works ─────────────────────────────
RUN rm -rf /var/www/localhost/htdocs/* && \
    mkdir -p /var/www/logs && \
    sed -i 's|logs/error.log|/proc/self/fd/2|g; s|logs/access.log|/proc/self/fd/1|g' /etc/apache2/httpd.conf /etc/apache2/conf.d/*.conf && \
    ln -sf /proc/self/fd/1 /var/www/logs/access.log && \
    ln -sf /proc/self/fd/2 /var/www/logs/error.log

# ── Copy frontend app ─────────────────────────────────────────────────────
COPY app/index.html app/style.css app/app.js app/logo.svg /var/www/localhost/htdocs/
RUN ln -sf /var/www/localhost/htdocs/logo.svg /var/www/localhost/htdocs/favicon.ico

# ── Generate MITRE playbooks at build time from live STIX data ───────────
# Directory layout inside the build context mirrors the deployed structure so
# each script's Path(__file__).resolve().parents[1] resolves to /tmp/build.
COPY scripts/ /tmp/build/scripts/
COPY app/playbooks-main/ /tmp/build/app/playbooks-main/

# Generate threat-group playbooks (fetches Enterprise ATT&CK STIX bundle)
RUN python3 /tmp/build/scripts/generate_mitre_group_playbooks.py

# Generate technique playbooks + mitre-index.json (fetches same STIX bundle)
RUN python3 /tmp/build/scripts/generate_technique_playbooks.py

# Scan all playbooks and update manifest tools[] coverage index
RUN python3 /tmp/build/scripts/update_manifest_tools.py

# ── Deploy playbooks-main to htdocs ──────────────────────────────────────
RUN mkdir -p /var/www/localhost/htdocs/playbooks-main && \
    cp -r /tmp/build/app/playbooks-main/. /var/www/localhost/htdocs/playbooks-main/ && \
    rm -rf /tmp/build

# ── Create empty playbooks-custom/ dir for the custom-override volume mount ────
# Files placed here by the operator (same relative path as playbooks-main/)
# take precedence when the frontend resolves playbook content.
RUN mkdir -p /var/www/localhost/htdocs/playbooks-custom

COPY --from=navigator-builder /build/attack-navigator/nav-app/dist/browser/ /var/www/localhost/htdocs/attack-navigator/
COPY app/cgi-bin/*.sh /var/www/localhost/cgi-bin/
COPY scripts/ /var/www/localhost/scripts/

RUN sed -i 's/\r$//' /var/www/localhost/cgi-bin/*.sh && \
    chmod +x /var/www/localhost/cgi-bin/*.sh

# ── Non-root user ─────────────────────────────────────────────────────────
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
RUN chown -R appuser:appgroup /var/www/localhost

# ── Create incident state directory for storing playbook step checklists ──
RUN mkdir -p /var/www/localhost/htdocs/incident-state && \
    chown -R appuser:appgroup /var/www/localhost/htdocs/incident-state

# ── Environment variables for robustness ──────────────────────────────────
ENV PYTHONUNBUFFERED=1 \
    NODE_ENV=production

USER appuser

# Custom-override playbooks are supplied via this volume at runtime.
# Mirror the playbooks-main/ structure; same filename overrides the built-in.
VOLUME ["/var/www/localhost/htdocs/playbooks"]

EXPOSE 8080

# ── Health check ──────────────────────────────────────────────────────────
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD wget --quiet --tries=1 --spider http://localhost:8080/ || exit 1

CMD ["httpd", "-D", "FOREGROUND"]

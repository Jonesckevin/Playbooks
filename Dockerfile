FROM node:20-alpine AS mitre-builder

WORKDIR /build
COPY scripts/generate-mitre-techniques.mjs /build/scripts/generate-mitre-techniques.mjs
RUN node /build/scripts/generate-mitre-techniques.mjs /build/mitre-techniques.json

FROM node:22-alpine AS navigator-builder

RUN apk add --no-cache git
WORKDIR /build
RUN git clone --depth 1 https://github.com/mitre-attack/attack-navigator.git
WORKDIR /build/attack-navigator/nav-app
RUN npm install
RUN npm run build -- --configuration production --base-href /attack-navigator/ --deploy-url /attack-navigator/

FROM alpine:3.19

# ── Install Apache, jq, Python, and bash ────────────────────────────────────
RUN apk add --no-cache apache2 jq python3 bash

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
    echo 'PassEnv SIEM_TOOL_1 SIEM_TOOL_2 SIEM_TOOL_3 SIEM_TOOL_4 SIEM_TOOL_5 SIEM_TOOL_6' >> /etc/apache2/conf.d/cgi.conf

# ── Logs → stdout/stderr so docker logs works ─────────────────────────────
RUN rm -rf /var/www/localhost/htdocs/* && \
    mkdir -p /var/www/logs && \
    sed -i 's|logs/error.log|/proc/self/fd/2|g; s|logs/access.log|/proc/self/fd/1|g' /etc/apache2/httpd.conf /etc/apache2/conf.d/*.conf && \
    ln -sf /proc/self/fd/1 /var/www/logs/access.log && \
    ln -sf /proc/self/fd/2 /var/www/logs/error.log

# ── Copy app ──────────────────────────────────────────────────────────────
COPY app/index.html app/style.css app/app.js app/logo.svg /var/www/localhost/htdocs/
RUN ln -sf /var/www/localhost/htdocs/logo.svg /var/www/localhost/htdocs/favicon.ico

# ── Generate queries at build time ────────────────────────────────────────
# Mirrors the expected directory structure so the script's path resolution works:
#   /tmp/build/scripts/update_playbook_queries.py  →  parents[1] = /tmp/build
#   /tmp/build/app/playbooks/                       →  PLAYBOOK_DIR resolved correctly
COPY scripts/ /tmp/build/scripts/
COPY app/playbooks/ /tmp/build/app/playbooks/
RUN python3 /tmp/build/scripts/update_playbook_queries.py

# ── Copy generated playbooks to htdocs ───────────────────────────────────
RUN mkdir -p /var/www/localhost/htdocs/playbooks && \
    cp -r /tmp/build/app/playbooks/. /var/www/localhost/htdocs/playbooks/ && \
    rm -rf /tmp/build

COPY --from=mitre-builder /build/mitre-techniques.json /var/www/localhost/htdocs/playbooks/mitre-techniques.json
COPY --from=navigator-builder /build/attack-navigator/nav-app/dist/browser/ /var/www/localhost/htdocs/attack-navigator/
COPY app/cgi-bin/*.sh /var/www/localhost/cgi-bin/
COPY scripts/ /var/www/localhost/scripts/

RUN sed -i 's/\r$//' /var/www/localhost/cgi-bin/*.sh && \
    chmod +x /var/www/localhost/cgi-bin/*.sh

# ── Create non-root user and group ────────────────────────────────────────
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# ── Persistent playbook storage — Docker named volume mounted at /playbooks
RUN mkdir -p /playbooks && chown appuser:appgroup /playbooks
RUN chown -R appuser:appgroup /var/www/localhost

USER appuser

VOLUME ["/playbooks"]

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=15s --retries=3 \
  CMD ["/var/www/localhost/cgi-bin/healthcheck.sh"]

CMD ["httpd", "-D", "FOREGROUND"]

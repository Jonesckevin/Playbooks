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

# ── Install Apache only — no Python, no extras ────────────────────────────
RUN apk add --no-cache apache2

# ── Enable mod_cgi ────────────────────────────────────────────────────────
RUN sed -i 's/#LoadModule cgi_module/LoadModule cgi_module/' /etc/apache2/httpd.conf

# ── Listen on 8080, set server name, disable directory listing ────────────
RUN sed -i 's/^Listen 80$/Listen 8080/'                            /etc/apache2/httpd.conf && \
    sed -i 's/#ServerName www.example.com:80/ServerName localhost/' /etc/apache2/httpd.conf && \
    sed -i 's/Options Indexes FollowSymLinks/Options FollowSymLinks/' /etc/apache2/httpd.conf

# ── CGI directory config ──────────────────────────────────────────────────
RUN echo '<Directory "/var/www/localhost/cgi-bin">'              >> /etc/apache2/conf.d/cgi.conf && \
    echo '    AllowOverride None'                                 >> /etc/apache2/conf.d/cgi.conf && \
    echo '    Options +ExecCGI'                                   >> /etc/apache2/conf.d/cgi.conf && \
    echo '    AddHandler cgi-script .sh'                          >> /etc/apache2/conf.d/cgi.conf && \
    echo '    Require all granted'                                >> /etc/apache2/conf.d/cgi.conf && \
    echo '</Directory>'                                           >> /etc/apache2/conf.d/cgi.conf && \
    echo 'ScriptAlias /cgi-bin/ /var/www/localhost/cgi-bin/'     >> /etc/apache2/conf.d/cgi.conf

# ── Logs → stdout/stderr so docker logs works ─────────────────────────────
RUN rm -rf /var/www/localhost/htdocs/* && \
    ln -sf /proc/self/fd/1 /var/log/apache2/access.log && \
    ln -sf /proc/self/fd/2 /var/log/apache2/error.log

# ── Copy app ──────────────────────────────────────────────────────────────
COPY app/index.html                 /var/www/localhost/htdocs/index.html
COPY app/style.css                  /var/www/localhost/htdocs/style.css
COPY app/app.js                     /var/www/localhost/htdocs/app.js
COPY app/playbooks/                  /var/www/localhost/htdocs/playbooks/
COPY --from=mitre-builder /build/mitre-techniques.json /var/www/localhost/htdocs/playbooks/mitre-techniques.json
COPY --from=navigator-builder /build/attack-navigator/nav-app/dist/browser/ /var/www/localhost/htdocs/attack-navigator/
COPY app/cgi-bin/save_playbook.sh   /var/www/localhost/cgi-bin/save_playbook.sh
COPY app/cgi-bin/load_playbooks.sh  /var/www/localhost/cgi-bin/load_playbooks.sh
COPY app/cgi-bin/update_playbook.sh /var/www/localhost/cgi-bin/update_playbook.sh
COPY app/cgi-bin/delete_playbook.sh /var/www/localhost/cgi-bin/delete_playbook.sh

RUN chmod +x /var/www/localhost/cgi-bin/*.sh

# ── Persistent playbook storage — Docker named volume mounted at /playbooks
RUN mkdir -p /playbooks && chown apache:apache /playbooks

VOLUME ["/playbooks"]

EXPOSE 8080

CMD ["httpd", "-D", "FOREGROUND"]

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
COPY index.html                 /var/www/localhost/htdocs/index.html
COPY cgi-bin/save_playbook.sh   /var/www/localhost/cgi-bin/save_playbook.sh
COPY cgi-bin/load_playbooks.sh  /var/www/localhost/cgi-bin/load_playbooks.sh
COPY cgi-bin/delete_playbook.sh /var/www/localhost/cgi-bin/delete_playbook.sh

RUN chmod +x /var/www/localhost/cgi-bin/*.sh

# ── Persistent playbook storage — Docker named volume mounted at /playbooks
RUN mkdir -p /playbooks && chown apache:apache /playbooks

VOLUME ["/playbooks"]

EXPOSE 8080

CMD ["httpd", "-D", "FOREGROUND"]

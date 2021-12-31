#!/usr/bin/env sh

php /var/apache2/templates/config-template.php > /etc/apache2/sites-available/001-reverse-proxy.conf

apache2-foreground

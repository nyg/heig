FROM php:7.3.6-apache
EXPOSE 80

COPY templates/ /var/apache2/templates/
COPY conf/ /etc/apache2/

RUN apt update && apt install -y tcpdump
RUN a2enmod proxy proxy_http proxy_balancer lbmethod_byrequests
RUN a2ensite 000-* 001-*

COPY setup.sh /usr/local/bin/rp-setup
CMD [ "rp-setup" ]

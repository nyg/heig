FROM php:7.3.5-apache
EXPOSE 80

COPY templates/ /var/apache2/templates/
COPY conf/ /etc/apache2/

RUN a2enmod proxy proxy_http
RUN a2ensite 000-* 001-*

COPY setup.sh /usr/local/bin/rp-setup
CMD [ "rp-setup" ]

# Documentation de la configuration
#
# Notre image docker est basée sur php:apache, qui propose un serveur Apache
# configuré avec la dernière version de PHP.
#
# On informe avec l'instruction EXPOSE 80 que le conteneur écoute sur le port
# 80. Cette instruction n'est pas obligatoire.
#
# Nous utilisons cette image afin que le serveur Apache y contenu fasse office
# de reverse proxy. La configuration de celui-ci est stockée dans le fichier
# conf/sites-available/001-reverse-proxy.conf.
#
# Nous utilisons l'instruction COPY afin de copier le contenu du répertoire
# conf dans le répertoire /etc/apache2.
#
# La configuration dans le fichier 000-default.conf permet de renvoyer une
# erreur 404 pour toutes les requêtes n'ayant pas demo.res.ch comme valeur pour
# l'entête Host.
#
# Le fichier 001-reverse-proxy.conf spécifie les règles suivantes :
# 1. toutes les requêtes demandant le chemin /api/addresses/ seront redirigées
#    vers notre conteneur res/express (IP 172.17.0.3:3000),
# 2. toutes les requêtes demandant le chemin / seront redirigées vers notre
#    conteneur res/apache (IP 172.17.0.2:80).

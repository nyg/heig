FROM php:apache

EXPOSE 80

COPY my-site/ /var/www/html/

# Documentation de la configuration
#
# Notre image docker est basée sur php:apache, qui propose un serveur Apache
# configuré avec la dernière version de PHP.
#
# On informe avec l'instruction EXPOSE 80 que le conteneur écoute sur le port
# 80. Cette instruction n'est pas obligatoire.
#
# Le contenu du site web est placé dans le répertoire my-site. Celui-ci est
# copié dans le répertoire /var/www/html de l'image docker grâce l'instruction
# COPY. La configuration Apache du site web est située dans le répertoire
# /etc/apache2/sites-available/

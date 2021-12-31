FROM php:7.3.5-apache
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
#
# Le contenu de notre site web a été téléchargé du site web bootstrapmade.com
# et nous l'avons ensuite épuré et personnalisé. Dans l'étape 4, le fichier
# js/address.js a été créé, il effectue une requête AJAX afin de chargé une
# adresse aléatoire, provenant de notre API /api/addresses/. Le fichier est
# chargé par la page index.html et la fonction loadAddress est appelée toutes
# les deux secondes.

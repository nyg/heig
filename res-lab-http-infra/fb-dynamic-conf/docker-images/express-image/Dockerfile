FROM node:12.3.1-alpine
EXPOSE 3000

COPY src/ /opt/app/

CMD [ "node", "/opt/app/index.js" ]

# Documentation de la configuration
#
# Notre image docker est basée sur node:alpine, qui propose la dernière version
# de Node.js dans une image très légère.
#
# On informe avec l'instruction EXPOSE 3000 que le conteneur écoute sur le port
# 3000. Cette instruction n'est pas obligatoire.
#
# Notre application Node.js est contenue dans le répertoire src, plus
# précisément dans le fichier index.js. Le fichier package.json a été généré
# avec npm et les dépendences change et express sont requises.
#
# Le répertoire src est copié dans le répertoire /opt/app grâce à l'instruction
# COPY.
#
# Notre application répond au requêtes GET possédant le chemin racine, et est
# démarée à la création du conteneur grâce à l'instruction CMD.

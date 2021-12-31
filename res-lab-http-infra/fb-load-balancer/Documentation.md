# RES – Documentation du Laboratoire *HTTP Infrastructure*

* **Auteurs** : Nathanaël Mizutani, Nikolaos Garanis
* **Date** : 10 juin 2019

## Step 1: Static HTTP server with apache httpd

Notre image Docker située dans le répertoire `apache-php-image` est basée sur `php:7.3.6-apache`, qui propose un serveur Apache configuré avec la version 7.3.6 de PHP.

On informe avec l'instruction `EXPOSE 80` que le conteneur écoute sur le port 80. Cette instruction n'est cependant pas obligatoire.

Nous avons récupéré un template fourni par le site web `bootstrapmade.com`. Ce template a ensuite été épuré et personnalisé. Son contenu se trouve dans le répertoire `my-site`. Celui-ci est copié dans le répertoire `/var/www/html` de l'image Docker grâce l'instruction `COPY`. La configuration Apache du site web est située dans le répertoire `/etc/apache2/sites-available/`.

Afin de tester notre configuration, nous effectuons les commandes suivantes :

```
docker build -t res/apache .
docker run --rm -d -p 8080:80 res/apache
```

Notre site web est alors disponible à l'adresse [localhost:8080](http://localhost:8080).

## Step 2: Dynamic HTTP server with express.js

Notre image Docker située dans le répertoire `express-image` est basée sur `node:12.4.0-alpine`, qui propose la version 12.4.0 de Node.js dans une image très légère.

Notre application Node.js est contenue dans le fichier `src/index.js`. Le fichier `package.json` a été généré avec `npm init` et les dépendances `chance` et `express` sont requises et peuvent être installées avec `npm install`. L'application génère et retourne un lot d'adresses aléatoires.

On informe avec l'instruction `EXPOSE 3000` que le conteneur écoute sur le port 3000. Cette instruction n'est cependant pas obligatoire. Le répertoire `src` est copié dans le répertoire `/opt/app` grâce à l'instruction `COPY`. Notre application répond au requêtes `GET` possédant le chemin racine, et est démarrée à la création du conteneur grâce à l'instruction `CMD`.

Afin de tester notre configuration, nous effectuons les commandes suivantes :

```
docker build -t res/express .
docker run --rm -d -p 3000:3000 res/express
```

Notre API est alors disponible à l'adresse [localhost:3000](http://localhost:3000).

## Step 3: Reverse proxy with apache (static configuration)

Notre image Docker située dans le répertoire `apache-reverse-proxy-image` est basée sur `php:7.3.6-apache`.

Nous utilisons cette image afin que le serveur Apache contenu dans celle-ci fasse office de reverse proxy. La configuration de celui-ci est stockée dans le fichier `conf/sites-available/`. La configuration du fichier `001-reverse-proxy` ne traîte que les requêtes ayant demo.res.ch comme Host. Couplée avec celle du fichier `000-default.conf` l'utilisation du nom de domaine demo.res.ch afin d'accéder au site web est nécessaire, l'adresse IP du proxy ne peut être utilisée.

Le fichier `001-reverse-proxy.conf` spécifie également les règles suivantes :

1. toutes les requêtes demandant le chemin `/api/students/` seront redirigées
vers notre conteneur res/express (IP 172.17.0.3:3000),
2. toutes les requêtes demandant le chemin `/` seront redirigées vers notre
conteneur res/apache (IP 172.17.0.2:80).

Les conteneurs statique et dynamique ne sont pas accessibles directement depuis l'Internet puisque nous n'exposons pas leur port avec Docker.

Nous utilisons l'instruction `COPY` afin de copier le contenu du répertoire `conf` dans le répertoire `/etc/apache2`. Les deux modules `proxy` et `proxy_http` sont activés avec la commande `a2enmod`, et les deux configurations avec la commande `a2ensite`.

Il est aussi nécessaire de faire en sorte que notre machine puisse résoudre le nom de domaine demo.res.ch. Pour cela une manipulation dépendante de l'OS est nécessaire.

Afin de tester notre configuration, nous effectuons les commandes suivantes :

```
docker build -t res/apache .
docker build -t res/express .
docker build -t res/apache-rp .

docker run --rm -d res/apache
docker run --rm -d res/express
docker run --rm -d -p 8080:80 res/apache-rp
```

L'API est ainsi disponible à l'adresse [demo.res.ch:8080/api/addresses/](http://demo.res.ch/api/addresses/) et le site web à l'adresse [demo.res.ch:8080/](http://demo.res.ch/).

Comme nous pouvons le voir, il est nécessaire que le conteneur res/apache ait soit voit attribuer l'adresse IP 172.17.0.2 et le conteneur res/express l'adresse IP 172.17.0.3. Ceci implique qu'aucun autre conteneur ne doit être démarré avant la manipulation mais aussi de démarrer les trois conteneurs dans l'ordre indiqué. Aussi, si nous voulons changer les adresses IP mentionnées dans la configuration Apache, l'image Docker doit être reconstruite.

## Step 4: AJAX requests with JQuery

Pour cette quatrième étape, nous avons créé le fichier `js/address.js`. Ce fichier effectue une requête AJAX afin de charger une adresse aléatoire, provenant de notre API `/api/addresses/`. Le fichier est chargé par la page `index.html` et la fonction `loadAddress` est appelée toutes les deux secondes.

Nous pouvons observer les requêtes AJAX et leur réponse en utilisant l'inspecteur Web du navigateur utilisé.

Sans le reverse proxy, la requête AJAX ne fonctionnerait pas. En effet, le script Javascript se trouverait sur le serveur 172.17.0.2 et voudrait faire une requête AJAX vers le serveur 172.17.0.3, requête qui aurait été bloquée par le navigateur à cause des restriction CORS (à cause des adresses IP différentes). Avec le reverse proxy, la requête est faite du domaine demo.res.ch au domaine demo.res.ch, le navigateur ne la bloque donc pas.

Afin de tester notre configuration, il suffit d'effectuer les mêmes commandes qu'à l'étape précédente.

## Step 5: Dynamic reverse proxy configuration

Le principe, afin de pouvoir spécifier les adresses IP des deux serveurs de manière "dynamique", c'est-à-dire au lancement du conteneur et non lors de la construction de l'image, est le suivant :

* écrire un template de configuration qui sera copié dans le conteneur (`templates/config-template.php`),
* créer un script qui persiste le template avec les valeurs données dans le répertoire de configuration d'Apache (`rp_setup.sh`) et démarre le serveur Apache,
* faire en sorte que ce script s'exécute lors du démarrage du conteneur et utilise les variables d'environnements spécifiées par la commande `docker run` (option `-e`).

Afin de tester notre configuration, il suffit d'effectuer les mêmes commandes qu'à l'étape précédente à l'exception de la dernière :

```
docker run --rm -e "STATIC_APP=172.17.0.x" -e "DYNAMIC_APP=172.17.0.y" -p 8080:80 res/apache-rp
```

## Additional steps to get extra points on top of the "base" grade

### Load balancing: multiple server nodes

Au lieu de rediriger vers une adresse IP, l'instruction `ProxyPass` redirige vers une URL de type `balancer://my-cluster`. C'est ensuite dans l'instruction `Proxy` que sont définis les membres du cluster, cela avec l'instruction `BalancerMember`. Dans le Dockerfile il ne faut pas oublier d'activer deux modules supplémentaires : `proxy_balancer` `lbmethod_byrequests`.

Nous avons garder le même principe de configuration dynamique avec un template PHP qu'à l'étape précédente. Ainsi, pour tester notre configuration, la commande suivante peut être utilisée :

```
docker run --rm -e "STATIC_NODES=172.17.0.7,172.17.0.6" -e "DYNAMIC_NODES=172.17.0.4,172.17.0.5" -p 8080:80 res/apache-rp
```

Afin de montrer que les requêtes soient bien réparties entre les différents conteneurs, il est possible de démarrer `tcpdump` dans le conteneur du reverse proxy. Par exemple :

```
docker exec -it <conteneur res/apache-rp> /bin/sh
tcpdump 'port 3000'
```

### Load balancing: round-robin vs sticky sessions

### Dynamic cluster management

### Management UI

## Source
* <https://hub.docker.com/_/php/>
* <https://www.digitalocean.com/community/tutorials/how-to-configure-the-apache-web-server-on-an-ubuntu-or-debian-vps>
* <https://help.ubuntu.com/lts/serverguide/httpd.html>
* <https://httpd.apache.org/>
* <https://startbootstrap.com/>
* <https://bootstrapmade.com>

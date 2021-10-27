# Application de messagerie

* **Date** : 16.10.2019
* **Auteurs** : Nikolaos Garanis, Samuel Mettler.

## Lancement de l'application

L'application peut être lancée dans un containeur Docker et sera disponible à  travers le port 8888 de la machine locale. Il suffit pour cela d'exécuter le script `start_app.sh` disponible à la racine du projet.

## Création de la base de données

La base de données peut être créée à partir du fichier `db/dump.sql` en exécutant le script `create_db.sh`. La base de données `database.sqlite` est alors créée dans le répertoire `site/databases/`.

### Administrateurs

Une fois la base de données créée, deux utilisateurs ont un accès administrateur. Leurs identifiants sont : niko/admin et samuel/password.

## Image Docker

Nous avons étendue l'image Docker fournie afin d'y modifier la configuration de PHP (voir le fichier `Dockerfile`), nous permettant de voir à l'écran les éventuelles erreurs et warnings PHP. Ces options ne doivent évidemment être utilisées que lors de la phase de développement.

## Users 

| Firstname | Lastname       | username  | password | active |
|-----------|----------------|-----------|----------|--------|
| Jérôme    | Bagnoud        | jerome    | mypwd    | yes    |
| Olivier   | Koffi          | olivier   | mypwd    | yes    |
| Stefan    | Dejanovic      | stefan    | mypwd    | yes    |
| Caroline  | Monthoux       | caroline  | mypwd    | yes    |
| Daniel    | Oliveira Paiva | daniel    | mypwd    | yes    |
| Florian   | Polier         | florian   | mypwd    | yes    |
| Nathan    | Séville        | nathan    | mypwd    | yes    |
| Victor    | Truan          | victor    | mypwd    | yes    |
| Jeremy    | Zerbib         | jeremy    | mypwd    | yes    |
| Mickael   | Bonjour        | mickael   | mypwd    | no     |
| Filipe    | Fortunato      | filipe    | mypwd    | no     |
| Baptiste  | Hardrick       | baptiste  | mypwd    | no     |
| Pierre    | Kohler         | pierre    | mypwd    | no     |
| Nathanaël | Mizutani       | nathanaël | mypwd    | no     |
| Edin      | Mujkanovic     | edin      | mypwd    | no     |
| Nemanja   | Pantic         | nemanja   | mypwd    | no     |
| Julien    | Quartier       | julien    | mypwd    | no     |
| David     | Simeonovic     | david     | mypwd    | no     |
| Jonathan  | Zaehringer     | jonathan  | mypwd    | no     |
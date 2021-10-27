# SYM — Rapport du Laboratoire 4

* **Date** : 12/01/2020
* **Auteurs** : Mickael Bonjour, Nikolaos Garanis et Samuel Mettler.

## Questions

### Capteurs

> **Une fois la manipulation effectuée, vous constaterez que les animations de la flèche ne sont pas fluides, il va y avoir un tremblement plus ou moins important même si le téléphone ne bouge pas. Veuillez expliquer quelle est la cause la plus probable de ce tremblement et donner une manière (sans forcément l’implémenter) d’y remédier.**

La cause la plus probable de ces tremblements c'est le nombre de données qui sont prises en comptes rapidement et leur précision. En effet, les capteurs nous envoient des données qui changent beaucoup à cause de la précision des données. On pourrait éviter ce genre de tremblements en faisant des moyennes sur un certains nombres de données reçues. Avec cela on pourrait éviter de changer les données tout le temps pour des petites variations. Une autre solution serait de ne pas changer les données si les variations sont inférieures à une certaine valeur prédéfinie.

### Bluetooth Low Energy

> **La caractéristique permettant de lire la température retourne la valeur en degrés Celsius, multipliée par 10, sous la forme d’un entier non-signé de 16 bits. Quel est l’intérêt de procéder de la sorte ? Pourquoi ne pas échanger un nombre à virgule flottante de type float par exemple ?**

Comme dit dans la question, l'entier envoyé l'est sur 16 bits alors qu'un float le serait sur 32 bits au moins. Cela nous ferait donc 2 octets de plus à envoyer, ce qui serait trop conséquent à envoyer dans certaines situations où la connexion est dégradée (par exemple).

Puis un float a aussi des problèmes de précision avec certains nombres, par exemple 1,1 ne peut être représenté de manière exacte (alors que dans notre cas il suffirait d'envoyer l'entier 11).

Une dernière raison pour ne pas utiliser des floats est que leur manipulation est plus complexe que des entiers ce qui peut être un problème pour les periphériques à faible puissance de calcul.

> **Le niveau de charge de la pile est à présent indiqué uniquement sur l’écran du périphérique, mais nous souhaiterions que celui-ci puisse informer le smartphone sur son niveau de charge restante. Veuillez spécifier la ou les caractéristiques qui composeraient un tel service, mis à disposition par le périphérique et permettant de communiquer le niveau de batterie restant via Bluetooth Low Energy. Pour chaque caractéristique, vous indiquerez les opérations supportées (lecture, écriture, notification, indication, etc.) ainsi que les données échangées et leur format.**

Nous definirions un service avec deux caractéristiques. La première permetterait de lire ou d'être notifié du niveau de charge de la pile. La deuxième permetterait à l'utilisateur du service de définir quand est-ce que le periphérique doit envoyer les notifications.

Opérations supportées par la première caractéristique :

* **lecture** : permetterait de récupérer le niveau de charge de la pile,
* **notification** : permetterait de notifier l'utilisateur du service lorsque le niveau de charge atteint certaines valeurs. Par exemple s'il s'approche de 0% (e.g. 20%, 10% et 5%) ou s'il atteint les 100%.

Tout comme pour la température, nous pourrions utiliser un entier non-signé de 16 bits afin de retourner un niveau de charge avec une précision d'une décimale (e.g. 123 pour 12,3%). Nous pourrions aussi utiliser un entier non-signé de 8 bits si la précision d'une décimale n'était pas voulue (e.g. 12 pour 12%).

Opérations supportéés par le deuxième caractéristique :

* **écriture** : permetterait de définir à quel niveau de charge le periphérique doit envoyer les notifications et quand (i.e. lorsque que le niveau de charge augmente ou diminue).
* (*optionnelle*) **lecture** : permetterait de récupérer les valeurs si, par exemple, le periphérique utilise des valeurs par défaut.

Le type de donnée utilisé serait un entier signé de 8 bits. Une valeur positive indiquerait que la notification doit avoir lieu lorsque le niveau de charge s'accroit et atteint la valeur indiquée. Une valeur négative lorsque le niveau de charge décroit et atteint la valeur indiquée.

Pour reprendre l'exemple donné pour la première caractéristique, on écrirait les valeurs suivantes : -20, -10, -5 et +100.

# Systèmes mobiles
## Laboratoire 1 — Introduction à Android

* **Auteurs** : Mickael Bonjour, Nikolaos Garanis, Samuel Mettler.

### Question 1

> Comment organiser les textes pour obtenir une application multi-langues (français, allemand, italien, langue par défaut : anglais) ?

Afin d'avoir une application multilangue il est nécessaire d'avoir plusieurs _strings.xml_ par langue. Chaque strings.xml contiendra les traductions en fonction des différentes langues.

> Que se passe-t-il si une traduction est manquante dans la langue par défaut ou dans une langue supplémentaire ?

Si une traduction est manquante alors il va prendre la prochaine possibilité de langue. Par exemple, si la langue de mon système est français mais qu'il manque un champ dans le _strings.xml_ français mais qu'il existe un _strings.xml_ d'une autre langue alors la valeur du champ sera celle du deuxième xml.

### Question 2

> Dans quel(s) dossier(s) devons-nous ajouter cette image ? Décrivez brièvement la logique derrière la gestion des ressources de type « image » sur Android.

Nous devons ajouter les icones dans le dossier `root/res/drawable` et ensuite mettre le nom adéquat pour la retrouver depuis android studio.
On y trouve les images matricielles (les images de type PNG, JPEG ou encore GIF) ainsi que des fichiers XML qui permettent de décrire des dessins (ce qui donne des images vectorielles qui ne se dégradent pas quand on les agrandit).

### Question 3

> Lorsque le login est réussi, vous êtes censé chaîner une autre Activity en utilisant un Intent. Si je presse le bouton "Back" de l'interface Android, que puis-je constater ?

Dans ce cas, l'application se ferme et on se retrouve là où on était auparavant.

>  Comment faire pour que l'application se comporte de manière plus logique ? Veuillez discuter de la logique derrière les activités Android.

Il faut supprimer l'appel à la méthode `finish()` (dans `MainActivity.onCreate()`). L'appel de `finish` va en fait détruire l'activité et il sera donc impossible d'y retourner lorsqu'on appuye sur le bouton *Back*.

### Question 4

> On pourrait imaginer une situation où cette seconde Activity fournit un résultat (par exemple l’IMEI ou une autre chaîne de caractères) que nous voudrions récupérer dans l'Activity de départ. Comment procéder ?

Dans l'activité de départ, au lieu d'utiliser `startActivity()` pour lancer la deuxième, on utilise `startActivityForResult()` et on implémente la méthode `onActivityResult()`. Dans la deuxième activité, il faut implémenté la méthode `onBackPressed()` afin de pouvoir transmettre la valeur de l'IMEI (par exemple).

### Question 5

> Vous noterez que la méthode `getDeviceId()` du TelephonyManager, permettant d’obtenir l’IMEI du téléphone, est dépréciée depuis la version 26 de l’API. Veuillez discuter de ce que cela implique lors du développement et de présenter une façon d’en tenir compte avec un exemple de code.

Il faut vérifier que la méthode que l'on souhaite utiliser existe selon la version de notre téléphone. En effet, certaine méthode n'existe pas avant la version 26 de l'API et vis-versa.

Par exemple :

```java
if (Build.VERSION.SDK_INT >= 26) {
    imei.setText(telephonyManager.getImei());
}
else {
    imei.setText(telephonyManager.getDeviceId());
}
```

> Veuillez réaliser un layout spécifique au mode paysage qui permet un affichage mieux adapté et indiquer comment faire pour qu’il soit utilisé automatiquement à l’exécution.

Afin de réaliser un layout spécifique pour le mode paysage il suffit d'appuyer sur "Create Landscape Variation".

### Question 7

> Décrivez brièvement à quelles occasions ces méthodes sont invoquées.

* `onCreate` est appelée lorsque l'utilisateur démarre l'application.
* `onRestart` est appelée lorsque l'utilisateur retourne sur l'activité (après avoir navigué vers une autre activité par exemple).
* `onStart` est appelée immédiatement après une des deux méthodes précédentes, l'activité va devenir visible à l'utilisateur.
* `onResume` est appelée lorsque l'activitée est prête à interagir avec l'utilisateur.
* `onPause` est appelée lorsque l'activtée n'est plus au premier plan mais est toujours visible. Soit l'utilisateur navigue vers une autre activité (onStop sera appelé) soit l'activité retourne au premier plan (onResume sera appelé)
* `onStop` est appelée lorsqu'une nouvelle activité est montrée à l'utilisateur.
* `onDestroy` est appelée lorsque l'activité fini d'elle même ou est détruite par le système (par exemple quand l'utilisateur quitte l'application).

> Vous expliquerez aussi l’enchainement de ces appels lorsque l’on passe d’une activité à l’autre.

Lorsque l'on passe de l'activité A à B les méthodes suivantes sont appelés :
* `A.onPause()`
* `B.onCreate()`
* `B.onStart()`
* `B.onResume()`
* `A.onStop()`

> Comment pouvez-vous factoriser votre code pour éviter de devoir réimplémenter ces méthodes dans chacune de vos activités ?

Nous pouvons créer une classe parente avec une implémentation basique de ces métodes (contenant par exemple seulement les appels de logs). Les classes de nos activités hériterons de cette classe.

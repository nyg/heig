<?php require_once 'util/user.php'; ?>

<nav>
    <ul>
        <li><a href="index.php">Accueil</a></li>
        <li><a href="send.php">Envoyer un message</a></li>
        <li><a href="pwd.php">Changer son mot de passe</a></li>
        <?= is_admin($_SESSION['id']) ? '<li><a href="admin.php">Administration</a></li>' : '' ?>
        <li><a href="login.php?logout">Déconnexion</a></li>
    </ul>
</nav>
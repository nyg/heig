<?php

require_once 'util/db.php';
require_once 'util/user.php';
require_once 'util/redirect.php';

session_start();

// perform logout if user has clicked the button
if (isset($_GET['logout'])) {
    $_SESSION = array();
}

// redirect to index.php if user is already logged in
if (isset($_SESSION['id'])) {
    redirect_to_index();
}

// if user has submitted login form, perform authentication
$error = '';
if (isset($_POST['submit'])) {

    $user = get_user_with_username($_POST['username']);
    if ($user && $user['password'] == $_POST['password']) {

        if ($user['active'] == 1) {
            $_SESSION['id'] = $user['id'];
            $_SESSION['name'] = $user['firstname'] . ' ' . $user['lastname'];
            redirect_to_index();
        }
        else {
            $error = 'Votre compte est inactif.';
        }
    }
    else {
        $error = 'L\'authentification a échouée.';
    }
}

$pageTitle = 'Authentification';
include 'include/html_header.php';

?>

    <div><?= $error ?></div>
    <form action="login.php" method="post" class="login">
        <label for="username">Nom d'utilisateur</label>
        <input type="text" id="username" name="username">
        <label for="password">Mot de passe</label>
        <input type="password" id="password" name="password">
        <button type="submit" name="submit">Authentification</button>
    </form>

<?php

include 'include/html_footer.php';
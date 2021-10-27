<?php

require_once 'util/db.php';
require_once 'util/user.php';
require_once 'util/redirect.php';

session_start();

// redirect to login if user is not logged in
if (!isset($_SESSION['id'])) {
    redirect_to_login();
}

$pageTitle = 'Changement du mot de passe';
include 'include/html_header.php';
include 'include/html_menu.php';

if (isset($_POST['submit']) && !empty($_POST['password'])) {

    if (update_password($_SESSION['id'], $_POST['password'])) {
        echo "Mot de passe changé !";
    }
    else {
        echo "Échec du changement de mot de passe !";
    }
}

?>

    <form action="pwd.php" method="post">
        <label for="password">Nouveau mot de passe</label>
        <input type="password" id="password" name="password">
        <button type="submit" name="submit">Valider</button>
    </form>

<?php

include 'include/html_footer.php';

<?php

require_once 'util/db.php';
require_once 'util/user.php';
require_once 'util/message.php';
require_once 'util/redirect.php';

session_start();

// redirect to login if user is not logged in
if (!isset($_SESSION['id'])) {
    redirect_to_login();
}

$pageTitle = 'Accueil';
include 'include/html_header.php';
include 'include/html_menu.php';

?>

    <table class="messages">
        <tr>
            <th>Date</th>
            <th>Expéditeur</th>
            <th>Sujet</th>
            <th>Lu</th>
            <th colspan="3"></th>
        </tr>

        <?php
        foreach (get_user_messages($_SESSION['id']) as $m) {
            $senderExists = !empty($m['sender']);

            echo '<tr>';
            echo '<td>' . $m['date'] . '</td>';
            echo '<td>' . ($senderExists ? $m['sender'] : '<em>Inconnu</em>') . '</td>';
            echo '<td class="wrap">' . $m['subject'] . '</td>';
            echo '<td>' . ($m['seen'] ? 'Oui' : 'Non') . '</td>';
            echo '<td>' . ($senderExists ? '<a href="send.php?message=' . $m['id'] . '">Répondre</a>' : '') . '</td>';
            echo '<td><a href="delete.php?delete=' . $m['id'] . '">Supprimer</a></td>';
            echo '<td><a href="read.php?message=' . $m['id'] . '">Ouvrir</a>' . '</td>';
            echo '</tr>';
        }
        ?>

    </table>

<?php

include 'include/html_footer.php';

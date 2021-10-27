<?php

require_once 'util/db.php';
require_once 'util/message.php';
require_once 'util/redirect.php';

session_start();

// redirect to login if user is not logged in
if (!isset($_SESSION['id'])) {
    redirect_to_login();
}

$message = get_message($_GET['message']);
$senderExists = !empty($message['sender']);

// mark message as read
is_read($_GET['message']);

$pageTitle = 'Lecture Message';
include 'include/html_header.php';
include 'include/html_menu.php';

?>

    <table class="messages">
        <tr>
            <td>Expéditeur</td>
            <td><?= ($senderExists ? $message['sender'] : '<em>Inconnu</em>') ?></td>
        </tr>
        <tr>
            <td>Date</td>
            <td><?= $message['date'] ?></td>
        </tr>
        <tr>
            <td>Sujet</td>
            <td><?= $message['subject'] ?></td>
        </tr>
        <tr>
            <td>Message</td>
            <td class="wrap"><?= $message['content'] ?></td>
        </tr>
    </table>

    <form action="send.php">
        <input type="hidden" name="message" value="<?= $message['id'] ?>">
        <input type="submit" value="Répondre">
    </form>

    <form action="delete.php">
        <input type="hidden" name="delete" value="<?= $message['id'] ?>">
        <input type="submit" value="Supprimer">
    </form>

<?php

include 'include/html_footer.php';

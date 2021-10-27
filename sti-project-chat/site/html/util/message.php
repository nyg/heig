<?php

function get_user_messages($userId)
{
    try {
        $stmt = $GLOBALS['db']->prepare('SELECT m.id, STRFTIME(\'%d.%m.%Y %H:%M\', m.date) date, m.subject, m.content, m.seen, u.firstname || \' \' || u.lastname sender FROM message m LEFT JOIN user u ON u.id = m.sender WHERE receiver = :receiver ORDER BY m.date DESC');
        $stmt->execute(['receiver' => $userId]);
        return $stmt->fetchAll();
    }
    catch (PDOException $e) {
        echo $e->getMessage();
        return false;
    }
}

function get_message($messageId)
{
    try {
        $stmt = $GLOBALS['db']->prepare('SELECT m.id, STRFTIME(\'%d.%m.%Y %H:%M\', m.date) date, m.subject, m.content, m.seen, u.id sender_id, u.firstname || \' \' || u.lastname sender FROM message m LEFT JOIN user u ON u.id = m.sender WHERE m.id = :id');
        $stmt->execute(['id' => $messageId]);
        return $stmt->fetch();
    }
    catch (PDOException $e) {
        echo $e->getMessage();
        return false;
    }
}

function is_read($messageId)
{
    try {
        $stmt = $GLOBALS['db']->prepare('UPDATE message SET seen = 1 WHERE id = :id');
        $stmt->execute(['id' => $messageId]);
        return $stmt->rowCount() == 1;
    }
    catch (PDOException $e) {
        echo $e->getMessage();
        return false;
    }
}

function send_message($date, $senderId, $receiverId, $subject, $content)
{
    try {
        $stmt = $GLOBALS['db']->prepare('INSERT INTO message (date, sender, receiver, subject, content) VALUES (:date, :sender, :receiver, :subject, :content)');
        $stmt->execute(['date' => $date, 'sender' => $senderId, 'receiver' => $receiverId, 'subject' => $subject, 'content' => $content]);
        return $stmt->rowCount() == 1;
    }
    catch (PDOException $e) {
        echo $e->getMessage();
        return false;
    }
}

function delete_message($idMessage)
{
    try {
        $stmt = $GLOBALS['db']->prepare('DELETE FROM message WHERE id = :idMessage');
        $stmt->execute(['idMessage' => $idMessage]);
        return $stmt->rowCount() == 1;
    }
    catch (PDOException $e) {
        echo $e->getMessage();
        return false;
    }
}

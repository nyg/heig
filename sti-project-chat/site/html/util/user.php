<?php

function is_admin($userId)
{
    try {
        $stmt = $GLOBALS['db']->prepare('SELECT admin FROM user WHERE id = :id');
        $stmt->execute(['id' => $userId]);
        $admin = $stmt->fetch();
        return $admin['admin'];
    }
    catch (PDOException $e) {
        echo $e->getMessage();
        return false;
    }
}

function delete_user($userId)
{
    try {
        $stmt = $GLOBALS['db']->prepare('DELETE FROM user WHERE id = :id');
        $stmt->execute(['id' => $userId]);
        return $stmt->rowCount() == 1;
    }
    catch (PDOException $e) {
        echo $e->getMessage();
        return false;
    }
}

function update_user($user)
{
    try {
        $stmt = $GLOBALS['db']->prepare('UPDATE user SET firstname = :firstname, lastname = :lastname, password = :password, admin = :admin, active = :active WHERE id = :id');
        $stmt->execute(['firstname' => $user['firstname'], 'lastname' => $user['lastname'], 'password' => $user['password'], 'admin' => isset($user['admin']), 'active' => isset($user['active']), 'id' => $user['id']]);
        return $stmt->rowCount() == 1;
    }
    catch (PDOException $e) {
        echo $e->getMessage();
        return false;
    }
}

function update_password($userId, $newPassword)
{
    try {
        $stmt = $GLOBALS['db']->prepare('UPDATE user SET password = :password WHERE id = :id');
        $stmt->execute(['password' => $newPassword, 'id' => $userId]);
        return $stmt->rowCount() == 1;
    }
    catch (PDOException $e) {
        echo $e->getMessage();
        return false;
    }
}

function create_user($user)
{
    if (empty($user['username']) || empty($user['firstname']) || empty($user['lastname']) || empty($user['password'])) {
        return false;
    }

    try {
        $stmt = $GLOBALS['db']->prepare('INSERT INTO user (firstname, lastname, username, password, admin, active) VALUES (:firstname, :lastname, :username, :password, :admin, :active)');
        $stmt->execute(['firstname' => $user['firstname'], 'lastname' => $user['lastname'], 'username' => $user['username'], 'password' => $user['password'], 'admin' => isset($user['admin']), 'active' => isset($user['active'])]);
        return $stmt->rowCount() == 1;
    }
    catch (PDOException $e) {
        echo $e->getMessage();
        return false;
    }
}

function get_all_users()
{
    try {
        $stmt = $GLOBALS['db']->query('SELECT * FROM user');
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }
    catch (PDOException $e) {
        echo $e->getMessage();
        return false;
    }
}

function get_user_with_id($userId)
{
    try {
        $stmt = $GLOBALS['db']->prepare('SELECT * FROM user WHERE id = :id');
        $stmt->execute(['id' => $userId]);
        return $stmt->fetch(PDO::FETCH_ASSOC);
    }
    catch (PDOException $e) {
        echo $e->getMessage();
        return false;
    }
}

function get_user_with_username($username)
{
    try {
        $stmt = $GLOBALS['db']->prepare('SELECT * FROM user WHERE username = :username');
        $stmt->execute(['username' => $username]);
        return $stmt->fetch();
    }
    catch (PDOException $e) {
        echo $e->getMessage();
        return false;
    }
}

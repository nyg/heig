<?php

try {
    $GLOBALS['db'] = new PDO('sqlite:/usr/share/nginx/databases/database.sqlite');
    $GLOBALS['db']->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
}
catch (PDOException $e) {
    echo $e->getMessage();
}

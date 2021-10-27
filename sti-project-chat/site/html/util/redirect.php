<?php

function redirect_to($page)
{
    header('Location: ' . $page);
    exit();
}

function redirect_to_index()
{
    redirect_to('index.php');
}

function redirect_to_login()
{
    redirect_to('login.php');
}

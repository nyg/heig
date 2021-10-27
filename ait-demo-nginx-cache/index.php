<?php

// function to generate resource fingerprint
function get_resource($filename)
{
    $assets_dir = 'assets/';
    $fp_dir = 'fingerprints/';

    // compute new filename which includes the file fingerprint
    $new_filename = $assets_dir . $fp_dir . hash_file('sha256', $assets_dir . $filename) . '-' . $filename;

    // create a symbolic link in the asset folder
    // normally this shouldn't be done at each page request but during server startup (for example)
    @symlink('../' . $filename, $new_filename);

    return $new_filename;
}

?>

<!doctype html>
<html lang="en">

<head>
    <title>Web Caching Website Example</title>
    <link href="<?= get_resource('favicon.ico') ?>" rel="shortcut icon">
    <link href="<?= get_resource('style.css') ?>" rel="stylesheet" type="text/css">
    <script src="<?= get_resource('script.js') ?>" type="text/javascript"></script>
</head>

<body>
    <h1>Cache-enabled website</h1>
    <img src="<?= get_resource('banner.jpg') ?>" alt="banner">
    <p>
        This content is generated dynamically (PHP): <span
                class="blink big"><?= substr(md5(rand()), 0, 7); ?></span>.<br>
        This content is generated dynamically (JS) : <span id="js-random" class="blink big"></span>.
    </p>
</body>

</html>

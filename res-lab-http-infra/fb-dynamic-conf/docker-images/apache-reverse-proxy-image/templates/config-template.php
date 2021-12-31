<VirtualHost *:80>
    ServerName demo.res.ch

    ProxyPass "/api/addresses/" "http://<?php echo getenv('DYNAMIC_APP'); ?>/"
    ProxyPassReverse "/api/addresses/" "http://<?php echo getenv('DYNAMIC_APP'); ?>/"

    ProxyPass "/" "http://<?php echo getenv('STATIC_APP'); ?>/"
    ProxyPassReverse "/" "http://<?php echo getenv('STATIC_APP'); ?>/"
</VirtualHost>

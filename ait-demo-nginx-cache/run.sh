#!/usr/bin/env sh

docker run --rm --name nginx-ait \
           -d -p 8080:80 \
           -v "$(pwd)":/app:rw \
           -v "$(pwd)"/configuration/nginx-site.conf:/opt/docker/etc/nginx/vhost.common.d/nginx-site.conf \
           webdevops/php-nginx:alpine-php7
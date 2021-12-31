#!/usr/bin/env sh

docker build -t res/apache -f apache-php-image/Dockerfile apache-php-image
docker build -t res/express -f express-image/Dockerfile express-image
docker build -t res/apache-rp -f apache-reverse-proxy-image/Dockerfile apache-reverse-proxy-image

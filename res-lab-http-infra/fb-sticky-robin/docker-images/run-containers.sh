#!/usr/bin/env sh

docker run --rm -d res/apache
docker run --rm -d res/express
docker run --rm -d -e "$1" -e "$2" -p 8080:80 res/apache-rp

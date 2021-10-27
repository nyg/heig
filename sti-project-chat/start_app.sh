#!/usr/bin/env sh

docker build -t php-dev .
docker run -ti --rm -v "$PWD/site":/usr/share/nginx/ -d -p 8888:80 --name sti_project --hostname sti php-dev

docker exec -u root sti_project service nginx start
docker exec -u root sti_project service php5-fpm start

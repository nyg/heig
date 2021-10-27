#!/usr/bin/env bash

# if first argument is empty, start all servers (f, d, l)
[ -z $1 ] && set fdl

# start firewall container and connect it to the dmz and lan networks
[[ $1 =~ "f" ]] &&
docker run -di --rm -e "TERM=xterm-color" --cap-add=NET_ADMIN --cap-add=NET_RAW \
           --name firewall -h Firewall srx/firewall-lab

# connect firewall to dmz and lan networks
docker network connect lan firewall
docker network connect dmz firewall

# start dmz container and expose port 80 for the webserver
[[ $1 =~ "d" ]] &&
docker run -di --rm -e "TERM=xterm-color" --cap-add=NET_ADMIN --cap-add=NET_RAW \
           --net dmz --name dmz -h ServerInDMZ -p 8080:80 srx/firewall-lab

# start lan container
[[ $1 =~ "l" ]] &&
docker run -di --rm -e "TERM=xterm-color" --cap-add=NET_ADMIN --cap-add=NET_RAW \
           --net lan --name lan -h ClientInLAN srx/firewall-lab

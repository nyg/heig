#!/bin/bash
#
# createmachines.sh    
#
# Creates and runs the containers Firewall, Client_in_LAN
# and Server_in_DMZ for the firewall labwork
# You need to run ./createnet.sh before running this script


docker run -itd --cap-add=NET_ADMIN --cap-add=NET_RAW --name firewall --hostname Firewall labofirewall /bin/bash
docker network connect lan firewall
docker network connect dmz firewall
docker run -itd --net lan --cap-add=NET_ADMIN --cap-add=NET_RAW --name lan --hostname Client_in_LAN labofirewall /bin/bash
docker run -itd --net dmz --cap-add=NET_ADMIN --cap-add=NET_RAW --name dmz --hostname Server_in_DMZ labofirewall /bin/bash

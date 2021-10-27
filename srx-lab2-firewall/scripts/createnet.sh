#!/bin/bash
#
# createnet.sh
#
# Creates the lan and dmz subnets in the Docker                         
# networking system for the firewall labwork

docker network create --subnet 192.168.200.0/24 dmz
docker network create --subnet 192.168.100.0/24 lan 


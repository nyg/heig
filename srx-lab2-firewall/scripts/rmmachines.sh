#!/bin/bash
#
# rmmachines.sh
#
# Deletes the containers for the firewall,
# the Server_in_DMZ and the Client_in_LAN
#
# WARNING : You will lose all your work !

docker rm firewall lan dmz -f

#!/bin/bash
#
# rmnet.sh
#
# Removes the dmz and lan subnetworks
# from the Docker networking system

docker network rm dmz
docker network rm lan

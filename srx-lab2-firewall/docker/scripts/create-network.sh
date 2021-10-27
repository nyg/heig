#!/usr/bin/env sh

# create dmz and lan networks
docker network create --subnet 192.168.200.0/24 dmz
docker network create --subnet 192.168.100.0/24 lan

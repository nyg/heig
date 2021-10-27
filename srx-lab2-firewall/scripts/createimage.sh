#!/bin/bash
#
# createimage.sh
#
# Creates the Docker image for the firewall labwork
# Needs a Dockerfile

docker build -t labofirewall .

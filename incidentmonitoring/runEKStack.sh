#!/bin/bash

if [ "$(id -u)" != "0" ]; then
   echo "Starting the EK stack requires root permissions"
   exit 1
fi

echo "Rising the maximum memory that virtual machines are allowed to map"
sudo sysctl -w vm.max_map_count=262144

echo "Starting EK-Stack..."
# -f to specify the file
# -d runs the containers in the background
docker-compose -f ./EKStack/docker-compose.yml up -d --build

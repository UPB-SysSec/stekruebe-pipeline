#!/bin/bash

# Name prefix to match containers
NAME_PREFIX="stekruebe-dummy-server"

# Create or overwrite the dns-hosts file
echo "" > ./hosts.txt

# Loop over all running containers and match the prefix in the container name
docker ps --format '{{.Names}}' | grep "^$NAME_PREFIX" | while read container_name; do
    # Get the container's IP address
    container_ip=$(docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$container_name")

    # Get the domains from the labels
    domains=$(docker inspect --format '{{.Config.Labels.domains}}' "$container_name" | tr -d '"[]')

    # Add each domain to the hosts file
    echo "$container_ip $domains" >> ./hosts.txt
done


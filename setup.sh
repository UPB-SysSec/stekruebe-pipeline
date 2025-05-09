#! /bin/bash
# update the ae-dummy-servers submodule
git submodule update --init --recursive

# if ./ae-dummy-servers/certs/ does not exist then
if [ ! -d "./ae-dummy-servers/certs/" ]; then
    # create the directory
    ./ae-dummy-servers/.create-certs.sh
fi

docker-compose -f ./ae-dummy-servers/docker-compose.yml up -d
# create hosts.txt
./generate_dummy_hosts.sh

# run local dns
./run_local_dns.sh

read -p "Setup complete. Press enter to shutdown..."
# after cancelling the script remove the docker-compose containers
docker-compose -f ./ae-dummy-servers/docker-compose.yml down
#! /bin/bash
# update the ae-dummy-servers submodule
git submodule update --init --recursive

# if ./ae-dummy-servers/certs/ is empty, create the certs
if [ ! -d "./ae-dummy-servers/certs" ] || [ -z "$(ls -A ./ae-dummy-servers/certs)" ]; then
    cd ./ae-dummy-servers || exit
    echo "Creating certificates..."
    ./.create_certs.sh
    cd ..
fi

docker-compose -f ./ae-dummy-servers/docker-compose.yml up -d
# create hosts.txt
./generate_dummy_hosts.sh

# run local dns
./run_local_dns.sh

function shutdown {
    echo "Shutting down..."
    # remove the dnsmasq container
    docker stop stekruebe-dnsmasq
    # remove the ae-dummy-servers containers
    docker-compose -f ./ae-dummy-servers/docker-compose.yml down
    exit 0
}
trap shutdown SIGINT

# wait for ctrl-c
echo "Press Ctrl+C to stop..."
read -r dummy
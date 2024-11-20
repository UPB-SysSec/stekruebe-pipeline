#!/bin/sh
cd "$(dirname $0)"

docker run \
    --name nginx_neo4j \
    -v "$(pwd)"/nginx.conf:/etc/nginx/conf.d/default.conf:ro \
    -v /etc/ssl/private/syssec-scanner6.cs.uni-paderborn.de.key:/key.pem:ro \
    -v /etc/ssl/private/syssec-scanner6.cs.uni-paderborn.de.pem:/cert.pem:ro \
    -p 8443:7474 \
    -p 7688:7687 \
    -d \
    nginx

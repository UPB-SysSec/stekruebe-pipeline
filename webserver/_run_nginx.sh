#!/bin/sh
cd "$(dirname "$0")"

_CERT_PATH="/etc/ssl/private/$(hostname).cs.uni-paderborn.de"

docker run \
    --name nginx_graph \
    -v "$(pwd)"/../graph_res:/usr/share/nginx/html:ro \
    -v "$(pwd)"/nginx.conf:/etc/nginx/conf.d/default.conf:ro \
    -v "$_CERT_PATH".key:/key.pem:ro \
    -v "$_CERT_PATH".pem:/cert.pem:ro \
    -p 9080:80 \
    -p 9443:443 \
    -d \
    nginx

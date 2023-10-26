#!/bin/sh
docker run \
    --name nginx_graph \
    -v /data/cdn_ticket/graph:/usr/share/nginx/html:ro \
    -v /data/cdn_ticket/webserver/nginx.conf:/etc/nginx/conf.d/default.conf:ro \
    -v /etc/ssl/private/snhebrok-eval.cs.uni-paderborn.de.key:/key.pem:ro \
    -v /etc/ssl/private/snhebrok-eval.cs.uni-paderborn.de.pem:/cert.pem:ro \
    -p 8080:80 \
    -p 8443:443 \
    -d \
    nginx

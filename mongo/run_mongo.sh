#!/bin/sh
cd "$(dirname "$0")" || exit

docker run -d -p 127.0.0.1:27017:27017 \
        -v /root/cert_key.pem:/cert_key.pem:ro \
        -v "./data/:/data/db" \
        -e "MONGO_INITDB_ROOT_USERNAME=mongoadmin" -e "MONGO_INITDB_ROOT_PASSWORD=573fc87d5dbd12e72f71faf6abe129c3518de9bd008c1a2681fd9e8a1e6677b3" \
        --name steckruebe-mongodb \
        --rm \
        -d \
        mongo --wiredTigerCacheSizeGB 8
        # --tlsMode requireTLS --tlsCertificateKeyFile /cert_key.pem --setParameter tlsUseSystemCA=true --tlsAllowConnectionsWithoutCertificates


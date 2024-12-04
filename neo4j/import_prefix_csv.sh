#!/bin/sh -e
cd "$(dirname "$0")"

docker stop steckruebe-prefix-database || true

docker run \
	-it \
	--rm \
	--name steckruebe-prefix-import \
	-v "$(pwd)"/neo4jdata:/data \
	-v "$(pwd)"/import:/import \
	neo4j:5.13.0 \
neo4j-admin database import full \
	--nodes /import/domains_header.csv,/import/domains.csv \
	--nodes /import/ips_header.csv,/import/ips.csv \
	--nodes /import/prefixes_header.csv,/import/prefixes.csv \
	--relationships /import/relationships_header.csv,/import/relationships.csv \
	--overwrite-destination=true \
	neo4j

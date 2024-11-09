#!/bin/sh -e
cd "$(dirname "$0")"

docker stop steckruebe-html-database || true

docker run \
	-it \
	--rm \
	--name steckruebe-html-import \
	-v "$(pwd)"/htmlneo4jdata:/data \
	-v "$(pwd)"/import:/import \
	neo4j:5.13.0 \
neo4j-admin database import full \
 	--nodes /import/initial_html_header.csv,/import/initial_html.csv \
	--nodes /import/resumption_html_header.csv,/import/resumption_html.csv \
	--relationships /import/html_edges_header.csv,/import/html_edges.csv \
	--skip-bad-relationships=true \
	--bad-tolerance=25000 \
	--overwrite-destination=true \
	neo4j

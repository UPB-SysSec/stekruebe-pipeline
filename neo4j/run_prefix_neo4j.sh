#!/bin/sh
# /import mount for bulk import script
# graph-data-science plugin for WCC
cd "$(dirname $0)"

# https://neo4j.com/docs/operations-manual/current/docker/ref-settings/
# values from
# docker run -it --rm neo4j:5.13.0 neo4j-admin server memory-recommendation --memory=16G
# restart with
# docker stop steckruebe-prefix-database; sleep 5; ./ticket-redirection/neo4j/run_neo4j.sh

docker run \
	-it \
	--name steckruebe-prefix-database \
	-v "$(pwd)"/neo4jdata:/data \
	--env NEO4J_PLUGINS='["graph-data-science"]' \
	--env NEO4J_AUTH='neo4j/IJj5fyYpeeWdvAXsxwuJuqlGQxZNDhLf' \
	-p 7474:7474 \
	-p 7687:7687 \
	-d \
	--rm \
	neo4j:5.13.0

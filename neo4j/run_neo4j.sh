#!/bin/sh
# /import mount for bulk import script
# graph-data-science plugin for WCC
docker run \
	-it \
	--name steckruebe-graph-database \
	-v /data/cdn_ticket/neo4j/neo4jdata:/data \
	--env NEO4J_PLUGINS='["graph-data-science"]' \
	--env NEO4J_AUTH='neo4j/IJj5fyYpeeWdvAXsxwuJuqlGQxZNDhLf' \
	-p 7474:7474 \
	-p 7687:7687 \
	-d \
	--rm \
	neo4j:5.13.0

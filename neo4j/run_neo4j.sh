#!/bin/sh
# /import mount for bulk import script
# graph-data-science plugin for WCC
cd "$(dirname $0)"

# https://neo4j.com/docs/operations-manual/current/docker/ref-settings/
# values from
# docker run -it --rm neo4j:5.13.0 neo4j-admin server memory-recommendation --memory=16G
# restart with
# docker stop steckruebe-graph-database; sleep 5; ./ticket-redirection/neo4j/run_neo4j.sh

docker run \
	-it \
	--name steckruebe-graph-database \
	-v "$(pwd)"/neo4jdata:/data \
	--env NEO4J_PLUGINS='["graph-data-science"]' \
	--env NEO4J_AUTH='neo4j/IJj5fyYpeeWdvAXsxwuJuqlGQxZNDhLf' \
	--env NEO4J_server_memory_heap_initial__size=5g \
	--env NEO4J_server_memory_heap_max__size=5g \
	--env NEO4J_server_memory_pagecache_size=7g \
	--env NEO4J_server_jvm_additional=-XX:+ExitOnOutOfMemoryError \
	--env NEO4J_server_bolt_thread__pool__max__size=400 \
	-p 7474:7474 \
	-p 7687:7687 \
	-d \
	--rm \
	neo4j:5.13.0

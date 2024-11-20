#!/bin/sh
# /import mount for bulk import script
# graph-data-science plugin for WCC
cd "$(dirname $0)"

# https://neo4j.com/docs/operations-manual/current/docker/ref-settings/
# values from
# docker run -it --rm neo4j:5.13.0 neo4j-admin server memory-recommendation --memory=16G

exist=$(docker ps -q -f "name=steckruebe-html-database")
if [ -n "$exist" ]; then
	docker kill steckruebe-html-database
	sleep 1
fi

docker run \
	-it \
	--name steckruebe-html-database \
	-v "$(pwd)"/htmlneo4jdata:/data \
	--env NEO4J_AUTH='neo4j/IJj5fyYpeeWdvAXsxwuJuqlGQxZNDhLf' \
	--env NEO4J_PLUGINS=\[\"apoc\"\] \
	--env NEO4J_server_memory_heap_initial__size=5g \
	--env NEO4J_server_memory_heap_max__size=5g \
	--env NEO4J_server_memory_pagecache_size=7g \
	--env NEO4J_server_jvm_additional=-XX:+ExitOnOutOfMemoryError \
	--env NEO4J_server_bolt_thread__pool__max__size=400 \
	--env NEO4J_server_http_advertised__address=syssec-scanner6.cs.upb.de:8443 \
	--env NEO4J_server_https_advertised__address=syssec-scanner6.cs.upb.de:8443 \
	--env NEO4J_server_bolt_advertised__address=syssec-scanner6.cs.upb.de:7687 \
	-p 7474:7474 \
	-p 7687:7687 \
	-d \
	--rm \
	neo4j:5.13.0

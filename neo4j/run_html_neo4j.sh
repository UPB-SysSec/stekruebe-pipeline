#!/bin/sh
# /import mount for bulk import script
# graph-data-science plugin for WCC
cd "$(dirname $0)"

# https://neo4j.com/docs/operations-manual/current/docker/ref-settings/
# values from
# docker run -it --rm neo4j:5.25.1 neo4j-admin server memory-recommendation --memory=24G

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
	-p 7474:7474 \
	-p 7687:7687 \
	-d \
	--rm \
	neo4j:5.25.1

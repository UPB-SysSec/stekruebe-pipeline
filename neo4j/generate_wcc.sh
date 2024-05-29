#!/bin/sh -e
cd "$(dirname "$0")"

cat generate_wcc.cypher | docker exec -i steckruebe-graph-database cypher-shell -u neo4j -p IJj5fyYpeeWdvAXsxwuJuqlGQxZNDhLf

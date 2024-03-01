docker run \
	-it \
	--rm \
	--name steckruebe-import \
	-v /data/cdn_ticket/neo4j/neo4jdata:/data \
	-v /data/cdn_ticket/neo4j/import:/import \
	neo4j:5.13.0 \
neo4j-admin database import full \
	--nodes /import/domains_header.csv,/import/domains.csv \
	--nodes /import/ips_header.csv,/import/ips.csv \
	--nodes /import/prefixes_header.csv,/import/prefixes.csv \
	--relationships /import/relationships_header.csv,/import/relationships.csv \
	--overwrite-destination=true \
	neo4j

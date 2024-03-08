#!/bin/sh -e
cd $(dirname $0)
export PYTHONUNBUFFERED=1

if [ -d "out" ]; then
    echo "out directory already exists. Please remove it first."
    exit 1
fi


echo "Gathering Tickets"

python3 1_gather_tickets.py tranco_XJJ9N.csv 100000

cd neo4j
docker stop steckruebe-graph-database || true

echo "Preparing for Neo4j"
python3 generate_bulk_csv.py
echo "Importing into Neo4j"
./import_csv.sh
echo "Starting Neo4j"
./run_neo4j.sh
sleep 30
echo "Generating Clusters"
./generate_wcc.sh
cd ..

echo "Running Scan (Sampling Neo4j)"
python3 2_perform_redirection.py

# echo "Running Evaluation"
# python3 3_evaluate.py

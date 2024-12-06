#!/bin/sh -e
cd $(dirname $0)
export PYTHONUNBUFFERED=1

if [ -d "out" ]; then
    echo "[!] out directory already exists. Please remove it first."
    exit 1
fi

if ! [ -d ".venv" ]; then
    echo "[#] Creating venv"
    python3 -m venv .venv
    . .venv/bin/activate
    pip install -r requirements.txt
else
    echo "[#] Using existing venv"
    . .venv/bin/activate
fi

docker stop steckruebe-html-database || true
docker stop steckruebe-prefix-database || true

echo "[#] Gathering Tickets"

date "+%s: %c"
python3 1_gather_tickets.py ../tranco_V9V2N.csv 1000000
date "+%s: %c"

cat out/7_merged_zgrab.r*.json > out/7_merged_zgrab_all.json

cd neo4j
docker stop steckruebe-prefix-database || true

if ! [ -d "import" ]; then
    mkdir import
fi

echo "[#] Preparing for Neo4j"
date "+%s: %c"
python3 generate_prefix_bulk_csv.py
date "+%s: %c"
echo "[ ] Importing into Neo4j"
./import_prefix_csv.sh
echo "[ ] Starting Neo4j"
./run_prefix_neo4j.sh
sleep 30
echo "[ ] Generating Clusters"
./generate_wcc.sh
cd ..

echo "[#] Running Scan (Sampling Neo4j)"
date "+%s: %c"
python3 2_perform_redirection.py
date "+%s: %c"

docker stop steckruebe-prefix-database

echo "[ ] Transfering scan results to neo4j"
date "+%s: %c"
python3 3_transfer_redirection_results_to_neo4j.py
# date "+%s: %c"

echo "[ ] Creating SIM edges"
date "+%s: %c"
python3 4_create_sim_edges.py
date "+%s: %c"

echo "[ ] Computing SIM edge values"
date "+%s: %c"
./5__wrapper.sh
date "+%s: %c"

echo "[#] DONE"

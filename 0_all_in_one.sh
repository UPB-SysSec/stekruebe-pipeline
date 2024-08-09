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


echo "[#] Gathering Tickets"

date "+%s: %c"
python3 1_gather_tickets.py ../tranco_XJLPN.csv 1000000
date "+%s: %c"

cat out/7_merged_zgrab.r*.json > out/7_merged_zgrab_all.json

cd neo4j
docker stop steckruebe-graph-database || true

if ! [ -d "import" ]; then
    mkdir import
fi

echo "[#] Preparing for Neo4j"
date "+%s: %c"
python3 generate_bulk_csv.py
date "+%s: %c"
echo "[ ] Importing into Neo4j"
./import_csv.sh
echo "[ ] Starting Neo4j"
./run_neo4j.sh
sleep 30
echo "[ ] Generating Clusters"
./generate_wcc.sh
cd ..

echo "[#] Running Scan (Sampling Neo4j)"
date "+%s: %c"
python3 2_perform_redirection.py
date "+%s: %c"

echo "Running Evaluation"
date "+%s: %c"
python3 3_evaluate.py
date "+%s: %c"

#!/bin/sh -e
cd $(dirname $0)
export PYTHONUNBUFFERED=1

if [ -d "out" ]; then
    echo "out directory already exists. Please remove it first."
    exit 1
fi

set -x

python3 run.py tranco_XJJ9N.csv 100000

cd neo4j
docker stop steckruebe-graph-database || true

python3 generate_bulk_csv.py
./import_csv.sh
./run_neo4j.sh
sleep 30
./generate_wcc.sh
cd ..

python3 sampling_neo4j.py

# TODO: evaluate results from mongodb

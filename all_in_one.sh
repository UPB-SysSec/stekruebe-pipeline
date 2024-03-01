#!/bin/sh -e
cd $(dirname $0)
set -x

python3 run.py tranco_7X8NX.csv

cd neo4j
python3 generate_bulk_csv.py
import_csv.sh
generate_wcc.sh
cd ..

python3 sampling_neo4j.py

# TODO: evaluate results from mongodb

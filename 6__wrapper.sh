#!/bin/bash

cd "$(dirname $0)"

LIMIT=180
SLEEP=60
RETRY=3

TRY=1
while true; do
    echo "Starting process... ($TRY/$RETRY)"
    start=$(date +%s)
    python3 6_confidence.py
    end=$(date +%s)
    runtime=$((end-start))

    if [ "$runtime" -gt "$LIMIT" ]; then
        # was running for long; probably not done yet
        echo "Process finished in $runtime seconds. Sleeping for $SLEEP seconds."
        TRY=1
    else
        # was fast; maybe done
        if [ "$TRY" -ge "$RETRY" ]; then
            echo "Process finished in $runtime seconds $RETRY times. Considering this as finished."
            break
        fi
        TRY=$((TRY+1))
        echo "Process finished in $runtime seconds. Trying again ($TRY/$RETRY)."
    fi

    if ! (docker ps | grep -q "steckruebe-html-database"); then
        echo "Neo4j is not running. Starting Neo4j..."
        ./neo4j/run_html_neo4j.sh
    fi
    sleep "$SLEEP"
done

#!/bin/bash

cd "$(dirname $0)"

LIMIT=60

while true; do
    start=$(date +%s)
    python3 3_evaluate.py
    end=$(date +%s)
    runtime=$((end-start))

    if [ "$runtime" -gt "$LIMIT" ]; then
        echo "Process finished in $runtime seconds. Sleeping for 60 seconds."
        sleep 60
    else
        echo "Process finished in $runtime seconds. Considering this as finished."
        break
    fi
done

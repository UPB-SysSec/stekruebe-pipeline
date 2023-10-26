#!/bin/bash -e
cd "$(dirname "$0")/clusters"

N=8487

mkdir -p svg
mkdir -p png

for i in $(seq $N -1 0); do
    echo "Rendering $i"
    sfdp -Tsvg "dot/$i.dot" -o "svg/$i.svg"
    echo "Converting to png $i"
    inkscape -w 250 -h 250 "svg/$i.svg" -o "png/$i.png"
done

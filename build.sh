#!/bin/bash

if [ $# -eq 0 ]; then
    echo "Usage: $0 <args...>"
    exit 1
fi

set -e 

cd nextAuth || exit
npm install
npm run build
cd ..
go build

./mtgban-website "$@"
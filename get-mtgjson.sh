#!/bin/bash

curl -O "https://mtgjson.com/api/v5/AllPrintings.json.xz"

xz -dc AllPrintings.json.xz | jq > /tmp/allprintings5.json.new

if [[ $? == 0 ]]
then
    mv /tmp/allprintings5.json.new ./allprintings5.json
fi

rm AllPrintings.json.xz

curl -O "https://mtgjson.com/api/v5/TcgplayerSkus.json.xz"

xz -dc TcgplayerSkus.json.xz | jq > /tmp/tcgskus.json.new

if [[ $? == 0 ]]
then
    mv /tmp/tcgskus.json.new ./tcgskus.json
fi

rm TcgplayerSkus.json.xz

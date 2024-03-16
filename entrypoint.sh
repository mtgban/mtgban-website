#!/bin/sh
if [ -z "$PORT" ]; then
    PORT=8080
fi

curl -O "https://mtgjson.com/api/v5/AllPrintings.json.xz"
xz -dc AllPrintings.json.xz | jq . > allprintings5.json
if [ $? -eq 0 ]; then
    echo "JSON file processed successfully."
else
    echo "Failed to process JSON file."
fi
rm -f AllPrintings.json.xz

./mtgbantu-website -port $PORT

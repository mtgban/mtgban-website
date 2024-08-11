#!/bin/bash

curl -O "https://lorcanajson.org/files/current/en/allCards.json.zip"

7z x allCards.json.zip

if [[ $? == 0 ]]
then
    mv allCards.json lorcana.json
fi

rm allCards.json.zip

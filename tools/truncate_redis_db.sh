#!/bin/bash

MAXDBS=10

if [[ -z $1 ]]
then
    echo "Usage: $0 <date_to_start_from>"
    echo "This tool will delete all data between the input start date and one year, from all the redis DBs"
    exit 1
fi

if [[ $1 != 20* ]]
then
    echo "Invalid year"
    exit 1
fi

YEAR=$(echo $1|cut -d '-' -f 1)
MONTH=$(echo $1|cut -d '-' -f 2)
SUBMONTH=${MONTH#"${MONTH%%[!0]*}"}

for i in $(seq 0 $MAXDBS)
do
    echo "DB $i"
    NEXTYEAR=$YEAR

    for j in $(seq 0 12)
    do
        THEMONTH=$(($SUBMONTH + $j))
        ENDMONTH=$(($THEMONTH % 13)) # extra month is correct due to how $NEXTYEAR is incremented
        if [[ $ENDMONTH == 0 ]]
        then
            NEXTYEAR=$(($YEAR + 1))
            continue
        fi

        for e in $(seq 1 31)
        do
            echo "go run delKey.go -db $i -key $(printf "%s-%02d-%02d" $NEXTYEAR $ENDMONTH $e)"
            go run delKey.go -db $i -key $(printf "%s-%02d-%02d" $NEXTYEAR $ENDMONTH $e)
        done
    done
done

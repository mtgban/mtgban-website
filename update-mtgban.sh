#!/bin/bash

# from https://stackoverflow.com/a/12704727/377439
TIP=$(git -c 'versionsort.suffix=-' ls-remote --exit-code --refs \
      --sort='version:refname' --tags  https://github.com/mtgban/go-mtgban.git '*.*.*' | \
      tail --lines=1 | cut -d "/" -f 3)

if [[ "${1}" == "local" ]]
then
    echo "Using local checkout at ../go-mtgban"
    go mod edit -replace github.com/mtgban/go-mtgban=../go-mtgban
    exit 0
elif [[ "${1}" == "remote" ]]
then
    echo "Removing local replace directive"
    go mod edit -dropreplace github.com/mtgban/go-mtgban
    exit 0
elif [[ "${1}" == "latest" ]]
then
    echo "Using latest hash"
    TIP=$(git ls-remote https://github.com/mtgban/go-mtgban.git HEAD | awk '{ print $1}')
elif [[ -e "${1}" ]]
then
    echo "unknown argument"
    exit 1
fi

go get -u github.com/mtgban/go-mtgban@$TIP

go mod tidy

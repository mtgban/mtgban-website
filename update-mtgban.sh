#!/bin/bash

# from https://stackoverflow.com/a/12704727/377439
TIP=$(git -c 'versionsort.suffix=-' ls-remote --exit-code --refs \
      --sort='version:refname' --tags  https://github.com/mtgban/go-mtgban.git '*.*.*' | \
      tail --lines=1 | cut -d "/" -f 3)

go get -u github.com/mtgban/go-mtgban@$TIP

go mod tidy

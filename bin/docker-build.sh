#!/usr/bin/env bash

set -xe

source .env

declare APP_VER
declare APP_IMG

docker build . \
  --build-arg APP_VER="${APP_VER}" \
  -t "${APP_IMG}":"${APP_VER}"-pipeline-test

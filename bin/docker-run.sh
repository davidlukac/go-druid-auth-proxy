#!/usr/bin/env bash

set -xe

source .env

declare APP_VER
declare APP_IMG

docker run --rm -it \
  --name druid-auth-proxy \
  -p 8443:443 \
  --env-file .runtime.local.env \
  -v "$(pwd)/certs/":/opt/app/certs/ \
  "${APP_IMG}":"${APP_VER}"



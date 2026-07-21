#!/bin/sh
set -eu

umask 077
cp -a /input/. /work/
tar -xf /opt/node-modules.tar -C /work
exec node --test \
  scripts/check-adr-numbering.test.mjs \
  scripts/check-flutter-coverage.test.mjs \
  scripts/check-host-ownership.test.mjs \
  scripts/check-provenance.test.mjs \
  scripts/generate-release-manifest.test.mjs \
  scripts/test-temporary-directory.test.mjs \
  scripts/tailnet-service.test.mjs

#!/usr/bin/env bash

set -uxo pipefail

# See: https://stackoverflow.com/a/73000327
trap "RC=1" ERR

ruff check --select I .
ruff format --check .
mypy int3/ tests/
pytest

exit $RC

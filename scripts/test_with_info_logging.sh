#!/usr/bin/env bash

set -xo pipefail

python3 -m pytest --log-cli-level=INFO "$@"

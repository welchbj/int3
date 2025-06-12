#!/usr/bin/env bash

set -uxo pipefail

ruff check --select I .
ruff format --check .
mypy int3/ tests/
pytest

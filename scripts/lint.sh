#!/usr/bin/env bash

set -uxo pipefail

python3 -m pytest
isort examples/ tests/ int3/
black examples/ tests/ int3/
flake8 examples/ tests/ int3/
mypy examples/ tests/ int3/

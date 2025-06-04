#!/usr/bin/env bash

set -uxo pipefail

ruff check --select I --fix .
ruff format .

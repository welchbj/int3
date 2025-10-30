#!/usr/bin/env bash

# llvm-config wrapper script to force static linking for llvmlite builds
# by intercepting --libs calls and adding --link-static.

REAL_LLVM_CONFIG="$(which llvm-config 2>/dev/null)"
if [[ -z "$REAL_LLVM_CONFIG" ]]; then
    echo "Error: Real llvm-config not found in PATH" >&2
    exit 1
fi

if [[ "$*" == *"--libs"* ]]; then
    exec "$REAL_LLVM_CONFIG" --link-static "$@"
else
    exec "$REAL_LLVM_CONFIG" "$@"
fi

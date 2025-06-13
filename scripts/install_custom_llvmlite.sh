#!/usr/bin/env bash

set -uxo pipefail

scripts_dir=$(dirname "$0")
int3_root_dir=$(dirname "$scripts_dir")

echo "$int3_root_dir"
exit

# TODO: Derive location of script

# Ensure Conda is installed, since we need it do install the llvmdev package.
# TODO

# Create a new Conda environment where we'll install llvmdev and build llvmlite
# TODO

# Install llvmdev so we don't have to build it from source.
conda install -c numba llvmdev

# Clone llvmlite source repo and checkout our known-good version.
# TODO
git clone https://github.com/numba/llvmlite.git
cd llvmlite
git checkout v0.44.0

# Apply our patch.
# TODO

# Test the newly-built llvmlite
# TODO

# Ensure the key component of our fork functions as expected
# TODO

# Copy over the built llvmlite into the int3 source tree.
# TODO

# Update llvmlite's import statements to use our vendored path.
cd TODO
find . -type f -exec sed -i "s/from llvmlite/from int3._vendored.llvmlite/" {} \;

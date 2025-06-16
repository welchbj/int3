#!/usr/bin/env bash

set -eo pipefail

scripts_dir=$(realpath $(dirname "$0"))
int3_root_dir=$(dirname "$scripts_dir")
llvmlite_patch_file="$int3_root_dir/patches/llvmlite_0.44.0_enable_all_asm_parsers.patch"

# Parse command-line options.
while [[ $# -gt 0 ]]; do
  case "$1" in
    -p|--python-version)
      python_version="$2"
      shift
      shift
      ;;
    -b|--build-name)
      build_name="$2"
      shift
      shift
      ;;
    *)
      echo "Invalid option: $1"
      exit 1
      ;;
  esac
done

if [[ -z "$python_version" ]]; then
    echo "Missing Python version (-p/--python-version)"
    exit 1
elif [[ -z "$build_name" ]]; then
    echo "Build directory (-b/--build-name)"
    exit 1
fi

if [[ -d "$int3_root_dir/int3/_vendored/llvmlite" ]]; then
    echo "Vendored llvmlite directory already exists"
    exit 1
fi

work_dir="$(mktemp -d)/$build_name"
mkdir -p "$work_dir"
echo "Using work directory: $work_dir"

# Ensure Conda is installed, since we need it do install the llvmdev package.
which conda || (echo "Conda must be installed to use this script" && exit 1)

# Move to our work directory.
pushd "$work_dir"

# Create a new Conda environment where we'll install llvmdev and build llvmlite
conda create --name "$build_name" python="$python_version" --yes
source ~/miniconda3/bin/activate "$build_name"

# Install llvmdev so we don't have to build it from source.
conda install -c numba llvmdev --yes

# Clone llvmlite source repo and checkout our known-good version.
git clone https://github.com/numba/llvmlite.git
pushd llvmlite
git checkout v0.44.0

# Apply our llvmlite patch.
git apply "$llvmlite_patch_file"

# Run the llvmlite build
python3 setup.py build

# Test the newly-built llvmlite
python3 -m llvmlite.tests

# Ensure the key component of our fork functions as expected
python3 -c "import llvmlite.binding as llvm; llvm.initialize_all_asmparsers()"

# Copy over the built llvmlite into the int3 source tree.
built_llvmlite_dir=$(find "$work_dir/llvmlite/build" -type d -name llvmlite)
echo "Copying over built llvmlite directory to int3 source tree"
cp -r "$built_llvmlite_dir" "$int3_root_dir/int3/_vendored"

popd
popd

# Update llvmlite's import statements to use our vendored path.
pushd "$int3_root_dir/int3"
find . -type f -exec sed -i "s/from llvmlite/from int3._vendored.llvmlite/" {} \;
popd

# Cleanup build artifacts.
conda deactivate
conda env remove --name "$build_name" --yes
rm -rf "$work_dir"

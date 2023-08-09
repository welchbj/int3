#!/usr/bin/env bash

set -uo pipefail

download_url=https://musl.cc
download_dir=/opt/musl.cc/downloads

if [[ ! -d $download_dir ]]; then
    sudo mkdir -p $download_dir
    sudo chown -R $(id -u):$(id -g) $download_dir
fi

pushd $download_dir >/dev/null

for url in $(curl -s $download_url | grep -- -cross); do
    tarball_name=$(echo $url | cut -d'/' -f4)

    if [[ -f $tarball_name ]]; then
        echo "Cached: $tarball_name"
        continue
    fi

    wget --quiet $url
    echo "Downloaded: $tarball_name"
done

popd >/dev/null

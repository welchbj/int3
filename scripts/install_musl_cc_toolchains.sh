#!/usr/bin/env bash

set -uo pipefail

download_url=https://musl.cc
base_dir=/opt/musl.cc
download_dir=$base_dir/downloads
install_dir=$base_dir/install
link_install_dir=/usr/local/bin

if [[ ! -d $download_dir ]]; then
    sudo mkdir -p $download_dir
    sudo chown -R $(id -u):$(id -g) $download_dir
fi

if [[ ! -d $install_dir ]]; then
    sudo mkdir -p $install_dir
    sudo chown -R $(id -u):$(id -g) $install_dir
fi

pushd $download_dir >/dev/null

for url in $(curl -s $download_url | grep -- -cross); do
    tarball_name=$(echo $url | cut -d'/' -f4)

    if [[ -f $tarball_name ]]; then
        echo "Download cached: $tarball_name"
        continue
    fi

    wget --quiet $url
    echo "Downloaded: $tarball_name"
done

popd >/dev/null
pushd $install_dir >/dev/null

for tarball in $(ls $download_dir/*.tgz); do
    triple=$(echo ${tarball##*/} | sed -e "s/-cross.tgz//")
    triple_install_dir=$install_dir/$triple

    if [[ -d $triple_install_dir ]]; then
        echo "Install cached: $triple_install_dir"
        continue
    fi

    mkdir -p $triple_install_dir
    tar xzf $tarball -C $triple_install_dir

    bin_dir=$triple_install_dir/$triple-cross/bin

    for bin in $(ls $bin_dir); do
        sudo  ln --force --symbolic $bin_dir/$bin $link_install_dir/$bin
    done

    echo "Installed: $triple_install_dir"
done

popd >/dev/null

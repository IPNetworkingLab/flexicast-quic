#!/bin/bash

git clone https://sigcomm-ccr:1H6Wq3BENAHz2BpMw1YZ@forge.uclouvain.be/inl/multicast-quic/multicast-quic.git
cd ~/multicast-quic
git checkout refactoring
git submodule update --init

sudo apt update
sudo apt-get -y install build-essential libevent-dev autoconf libtool-bin make cmake iperf libmicrohttpd-dev
sudo apt-get -y install linux-tools-common linux-tools-generic linux-tools-`uname -r`
sudo apt-get -o Dpkg::Options::="--force-confold" upgrade -q -y --force-yes
sudo apt install -y cmake tmux htop
curl https://sh.rustup.rs -sSf | sh -s -- -y
source "$HOME/.cargo/env"


cd apps/
cargo build --release --bins

# Clone experiment scripts.
cd ~
git clone https://sigcomm-ccr:1H6Wq3BENAHz2BpMw1YZ@forge.uclouvain.be/inl/multicast-quic/flexicast-experiments.git
cd flexicast-experiments/dummy
git checkout http3
cargo build --release --bins

# Install ffmpeg and G-streamer.
DEBIAN_FRONTEND=noninteractive sudo apt install -y ffmpeg
DEBIAN_FRONTEND=noninteractive sudo apt-get install -y libgstreamer1.0-dev libgstreamer-plugins-base1.0-dev libgstreamer-plugins-bad1.0-dev gstreamer1.0-plugins-base gstreamer1.0-plugins-good gstreamer1.0-plugins-bad gstreamer1.0-plugins-ugly gstreamer1.0-libav gstreamer1.0-tools gstreamer1.0-x gstreamer1.0-alsa gstreamer1.0-gl gstreamer1.0-gtk3 gstreamer1.0-qt5 gstreamer1.0-pulseaudio

# Create common directory for experiments.
sudo mkdir -p /home/louisna/flexicast-experiments/perf
sudo chmod -R 777 /home

pip install pandas
pip3 install pandas
#!/bin/bash

apt-get update
apt-get install -y build-essential
apt-get remove --purge nvidia*
apt-get autoremove

BASE="/vagrant"

CUDA="https://developer.nvidia.com/compute/cuda/9.1/Prod/local_installers/cuda_9.1.85_387.26_linux"
CUDA_INSTALL="$BASE/provision/cuda.run"
RSTUDIO_SERVER="https://download2.rstudio.org/rstudio-server-1.1.383-amd64.deb"
RSTUDIO_SERVER_INSTALL="$BASE/provision/rstudio-server.deb"
WGET_OPTS="-4 -q"

mkdir -p $CUDA_INSTALL
[[ -f $CUDA_INSTALL ]] || wget $WGET_OPTS $CUDA -O $CUDA_INSTALL

chmod u+x $CUDA_INSTALL
$CUDA_INSTALL --silent --driver --toolkit --verbose

grep cuda /etc/profile || cat >> /etc/profile <<EOF
export PATH=/usr/local/cuda/bin${PATH:+:${PATH}}
export LD_LIBRARY_PATH=/usr/local/cuda/lib64${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}
export CUDA_HOME=/usr/local/cuda
EOF
source /etc/profile

grep nouveau /etc/modprobe.d/blacklist.conf || cat >> /etc/modprobe.d/blacklist.conf <<EOF
blacklist vga16fb
blacklist nouveau
blacklist rivafb
blacklist nvidiafb
blacklist rivatv
EOF

update-initramfs -u

rmmod -f nvidia_uvm
rmmod nvidia
rmmod nouveau

nvidia-smi

#curl -s -L https://nvidia.github.io/nvidia-container-runtime/gpgkey | \
#  sudo apt-key add -
#curl -s -L https://nvidia.github.io/nvidia-container-runtime/debian9/amd64/nvidia-container-runtime.list | \
#  sudo tee /etc/apt/sources.list.d/nvidia-container-runtime.list
#sudo apt-get update
#sudo apt-get install -y nvidia-container-runtime
#
#sudo mkdir -p /etc/systemd/system/docker.service.d
#sudo tee /etc/systemd/system/docker.service.d/override.conf <<EOF
#[Service]
#ExecStart=
#ExecStart=/usr/bin/dockerd --host=fd:// --add-runtime=nvidia=/usr/bin/nvidia-container-runtime
#EOF
#sudo systemctl daemon-reload
#sudo systemctl restart docker

#sudo tee /etc/docker/daemon.json <<EOF
#{
#    "runtimes": {
#        "nvidia": {
#            "path": "/usr/bin/nvidia-container-runtime",
#            "runtimeArgs": []
#        }
#    }
#}
#EOF
#sudo pkill -SIGHUP dockerd
#
#docker run --runtime=nvidia --rm nvidia/cuda nvidia-smi

# Add the package repositories
#curl -s -L https://nvidia.github.io/nvidia-docker/gpgkey | apt-key add -
#curl -s -L https://nvidia.github.io/nvidia-container-runtime/ubuntu16.04/amd64/nvidia-container-runtime.list | tee /etc/apt/sources.list.d/nvidia-container-runtime.list
#sudo apt-get update

# Install nvidia-docker2 and reload the Docker daemon configuration
#sudo apt-get install -y nvidia-docker-runtime
#sudo pkill -SIGHUP dockerd

#docker run --runtime=nvidia --rm nvidia/cuda nvidia-smi
#reboot
#apt-get install -y python3 python3-pip
pip3 install --upgrade pip
pip3 install --upgrade jupyter

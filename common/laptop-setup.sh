#!/bin/bash
# Run as root -- I know, very safe :)
# Tested on 64bit Ubuntu 18.04 LTS

# Check for any broken links and version updates before running
VBOX_REPO_KEY_URL="https://www.virtualbox.org/download/oracle_vbox_2016.asc"
DOCKER_REPO_KEY_URL="https://download.docker.com/linux/ubuntu/gpg"
VAGRANT_URL="https://releases.hashicorp.com/vagrant/2.2.7/vagrant_2.2.7_x86_64.deb"
VSCODE_URL="https://go.microsoft.com/fwlink/?LinkID=760868"
VIRTUALBOX="virtualbox-6.1"

export DEBIAN_FRONTEND=noninteractive
apt-get -q -y dist-upgrade
apt-get install -q -y apt-transport-https ca-certificates curl wget gnupg-agent software-properties-common libterm-readline-perl-perl debconf-utils libsecret-1-0 libsecret-common libxkbfile1

curl -fsSL $VBOX_REPO_KEY_URL | apt-key add -
curl -fsSL $DOCKER_REPO_KEY_URL | apt-key add -

add-apt-repository -y "deb [arch=amd64] https://download.virtualbox.org/virtualbox/debian $(lsb_release -cs) contrib"
add-apt-repository -y "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"

apt-get update -q
echo "wireshark-common wireshark-common/install-setuid boolean true" | debconf-set-selections # Avoid the wireshark install prompt
apt-get install -q -y docker-ce docker-ce-cli containerd.io python3 python3-pip git htop jq iftop iproute2 net-tools dnsutils strace dstat vim nano tmux screen curl mlocate tcpdump bash-completion tree telnet man-db pcregrep dwdiff aptitude wireshark tshark ethtool chromium-browser firefox sudo snapd $VIRTUALBOX
snap install yq # If snapd was just installed, the user might need to log out and back in before installing, but missing yq is a minor problem, so I am not going to bother here
pip3 install --upgrade pip
apt-get -q -y autoremove
apt-get -q -y autoclean


cd /tmp
wget -O vagrant.deb $VAGRANT_URL
dpkg -i vagrant.deb

wget -O code.deb $VSCODE_URL
dpkg -i code.deb

#Create and configure student user
if [[ ! -d "/home/student" ]]; then
  # U: student P: student
  useradd -m --shell /bin/bash -p '$6$oAqTd7tM$gpCt7kPAVIyHqjxVFMNE8v6wt1GzfzsVmibGJF6beFF050bTpT.o4SvoVVLHsZo5WSi5NscQ3B9DrtSmHa7ee.' student
fi
adduser student docker
adduser student vboxusers
echo 'student ALL=(ALL) ALL' > /etc/sudoers.d/student

su -l student -c 'cd /home/student; git clone https://github.com/ccdcoe/CDMCS.git'

# Pre-download vagrant boxes
su -l student -c 'vagrant box add --provider virtualbox --force --clean ubuntu/bionic64'
su -l student -c 'vagrant box add --provider virtualbox --force --clean generic/ubuntu1804'

#Clean up
echo -n "" > ~/.bash_history
su -l student -c 'echo -n "" > ~/.bash_history'
history -c

exit 0

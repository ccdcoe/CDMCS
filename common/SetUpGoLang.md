# go setup

```

GOLANG="go1.7.4.linux-amd64.tar.gz"

cd /tmp
wget -q -4 https://storage.googleapis.com/golang/$GOLANG
tar -zxvf $GOLANG -C /usr/local/ > /dev/null 2>&1
echo 'export GOROOT=/usr/local/go' >> ~/.bashrc
echo 'export PATH=$PATH:$GOROOT/bin:$GOPATH/bin' >> ~/.bashrc
echo 'export GOPATH=/opt/udfs' >> ~/.bashrc
export GOROOT=/usr/local/go
export PATH=$PATH:$GOROOT/bin:$GOPATH/bin
export GOPATH=/opt/udfs
mkdir -p /opt/udfs
cd /opt/udfs
go version
go env

```

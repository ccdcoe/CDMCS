#

> Go, also known as golang, is a computer programming language whose development began in 2007 at Google, and it was introduced to the public in 2009. Golang was explicitly engineered to thrive in projects built by large groups of programmers with different skill levels.
> Concurrency, easy one binary deploy with yet fast build times.

# go setup

```

GOLANG="go1.7.4.linux-amd64.tar.gz"

cd /tmp
wget -q -4 https://storage.googleapis.com/golang/$GOLANG
tar -zxvf $GOLANG -C /usr/local/ > /dev/null 2>&1
echo 'export GOROOT=/usr/local/go' >> ~/.bashrc
echo 'export GOPATH=/opt/go' >> ~/.bashrc
echo 'export PATH=$PATH:$GOROOT/bin:$GOPATH/bin' >> ~/.bashrc
export GOROOT=/usr/local/go
export GOPATH=/opt/go
export PATH=$PATH:$GOROOT/bin:$GOPATH/bin
mkdir -p /opt/go
cd /opt/go
go version
go env

```

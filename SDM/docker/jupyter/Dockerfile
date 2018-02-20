FROM jupyter/datascience-notebook

ENV DEBIAN_FRONTEND noninteractive
ENV INITRD No
ENV LANG en_US.UTF-8

USER root
RUN echo "deb http://download.opensuse.org/repositories/network:/messaging:/zeromq:/release-stable/Debian_9.0/ ./" >> /etc/apt/sources.list
RUN wget https://download.opensuse.org/repositories/network:/messaging:/zeromq:/release-stable/Debian_9.0/Release.key -O- | sudo apt-key add
RUN apt-get update && apt-get install -y pkg-config libzmq3-dev && apt-get remove && apt-get autoremove && apt-get clean

USER jovyan
RUN conda install --quiet --yes "r-mvtnorm"

ENV GOVERSION 1.9.4
ENV GOROOT /home/jovyan/go
ENV GOPATH /home/jovyan/gospace
ENV PATH=$PATH:${GOPATH}/bin:${GOROOT}/bin

RUN mkdir -p ${GOPATH}
RUN cd /home/jovyan && wget -4 -q https://storage.googleapis.com/golang/go${GOVERSION}.linux-amd64.tar.gz && tar zxf go${GOVERSION}.linux-amd64.tar.gz -C /home/jovyan && rm go${GOVERSION}.linux-amd64.tar.gz
RUN go get golang.org/x/tools/cmd/goimports
RUN go get -u github.com/gopherdata/gophernotes
RUN mkdir -p ~/.local/share/jupyter/kernels/gophernotes
RUN cp ${GOPATH}/src/github.com/gopherdata/gophernotes/kernel/* ~/.local/share/jupyter/kernels/gophernotes 

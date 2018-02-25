FROM jupyter/datascience-notebook

ENV DEBIAN_FRONTEND noninteractive
ENV INITRD No
ENV LANG en_US.UTF-8

USER root
RUN echo "deb http://download.opensuse.org/repositories/network:/messaging:/zeromq:/release-stable/Debian_9.0/ ./" >> /etc/apt/sources.list
RUN wget https://download.opensuse.org/repositories/network:/messaging:/zeromq:/release-stable/Debian_9.0/Release.key -O- | sudo apt-key add
RUN apt-get update && apt-get install -y pkg-config libzmq3-dev wget && apt-get remove && apt-get autoremove && apt-get clean

USER jovyan

ENV GOVERSION 1.9.4
ENV GOROOT /home/jovyan/go
ENV GOPATH /home/jovyan/gospace
ENV PATH=$PATH:${GOPATH}/bin:${GOROOT}/bin

RUN mkdir -p ${GOPATH}
RUN cd /home/jovyan && wget -4 -q https://storage.googleapis.com/golang/go${GOVERSION}.linux-amd64.tar.gz && tar zxf go${GOVERSION}.linux-amd64.tar.gz -C /home/jovyan && rm go${GOVERSION}.linux-amd64.tar.gz
RUN go get golang.org/x/tools/cmd/goimports

# nodejs
ENV NODE_VER "v8.9.4"
RUN wget -4 -q https://nodejs.org/dist/${NODE_VER}/node-${NODE_VER}-linux-x64.tar.gz && tar -xzf node-${NODE_VER}-linux-x64.tar.gz -C /home/jovyan && rm node-${NODE_VER}-linux-x64.tar.gz 
ENV PATH=$PATH:/home/jovyan/node-${NODE_VER}-linux-x64/bin

# nodejs kernel for jupyter
RUN git clone https://github.com/notablemind/jupyter-nodejs.git && cd jupyter-nodejs && mkdir -p ~/.ipython/kernels/nodejs/ && npm install && node install.js && npm run build && npm run build-ext 

# Go kernel for jupyter
RUN go get github.com/yunabe/lgo/cmd/lgo && go get -d github.com/yunabe/lgo/cmd/lgo-internal
ENV LGOPATH /home/jovyan/lgo
RUN mkdir -p ${LGOPATH} && lgo install && ${GOPATH}/src/github.com/yunabe/lgo/bin/install_kernel

# go packages
RUN go get github.com/spaolacci/murmur3
RUN go get github.com/Shopify/sarama
RUN go get github.com/linkedin/goavro
RUN go get github.com/influxdata/influxdb/client/v2
RUN go get github.com/elastic/go-elasticsearch
RUN go get github.com/olivere/elastic

# R packages
RUN conda install --quiet --yes "r-mvtnorm"
RUN conda install --quiet --yes "r-forecast"
RUN conda install --quiet --yes "r-tm" "r-lsa"
RUN conda install --quiet --yes "r-cluster" "r-fpc"
RUN conda install --quiet --yes "r-gridextra"
RUN conda install --quiet --yes "r-snowballc"

# python packages
RUN conda install --quiet --yes "elasticsearch"
RUN conda install --quiet --yes "kafka-python"
RUN conda install --quiet --yes "python-avro"
RUN pip install --upgrade "influxdb"

FROM ubuntu:16.04

RUN echo "deb http://cran.rstudio.com/bin/linux/ubuntu xenial/" | tee -a /etc/apt/sources.list && \
gpg --keyserver keyserver.ubuntu.com --recv-key E084DAB9 && \
gpg -a --export E084DAB9 | apt-key add -

RUN apt-get update && apt-get install -y sudo curl openssl libssl-dev libcurl4-openssl-dev ed gdebi-core wget libxslt1-dev libxkbcommon-dev libxcb-xkb-dev libxslt1-dev libgstreamer-plugins-base0.10-dev libgl1-mesa-glx libgl1-mesa-dri r-base r-base-dev texlive texlive-latex-extra latexmk texlive-lang-european && \
apt-get build-dep -y r-cran-rgl && \
rm -rf /var/lib/apt/lists/*

# not actually needed as packages can be installed into the project folder under ./R/, as regular user
#COPY packages.R /tmp/packages.R
#RUN Rscript /tmp/packages.R

ARG rstudio="rstudio-xenial-1.1.423-amd64.deb"
ENV rstudio=${rstudio}

RUN apt-get update && wget https://download1.rstudio.org/${rstudio} && \
gdebi -n ${rstudio} && \
rm ${rstudio} && \
rm -rf /var/lib/apt/lists/*

ARG user="vagrant"
ENV user=${user}

# Replace 1000 with your user / group id
RUN export uid=1000 gid=1000 && \
    mkdir -p /home/${user} && \
    echo "${user}:x:${uid}:${gid}:${user},,,:/home/${user}:/bin/bash" >> /etc/passwd && \
    echo "${user}:x:${uid}:" >> /etc/group && \
    adduser ${user} video && \
    chown ${uid}:${gid} -R /home/${user} && \
    mkdir /data && chown ${uid}:${gid} /data


USER ${user}
ENV HOME /home/${user}
WORKDIR /home/${user}
CMD /usr/bin/rstudio

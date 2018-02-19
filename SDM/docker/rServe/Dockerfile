FROM r-base

RUN apt-get update && apt-get install -y psmisc wget sudo openssl libssl-dev libcurl4-openssl-dev build-essential && rm -rf /var/lib/apt/lists/*

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

#RUN R -e 'install.packages(c("httr", "curl", "jsonlite"), repos = "http://cran.us.r-project.org")'
#RUN R -e 'install.packages(c("gpuR"), repos = "http://cran.us.r-project.org")'

RUN R -e 'install.packages(c("Rserve"), repos = "http://cran.us.r-project.org")'

USER ${user}
ENV HOME /home/${user}
WORKDIR $HOME
#ENTRYPOINT ["R", "CMD", "Rserve"]

EXPOSE 6311
ENTRYPOINT R -e "Rserve::run.Rserve(remote=TRUE)"

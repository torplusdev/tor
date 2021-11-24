FROM debian:10 AS cache
WORKDIR /app
COPY . .
RUN rm -rf docker

FROM debian:10
RUN echo deb http://ftp.debian.org/debian buster-backports main >> /etc/apt/sources.list.d/backports.list
RUN echo deb-src http://ftp.debian.org/debian buster-backports main >> /etc/apt/sources.list.d/backports.list

# Installing Library & Package
RUN apt-get update && \
apt-get install -y expect torsocks \
    links \
    dos2unix git make cmake build-essential pkg-config \
    libevent-dev libssl-dev zlib1g-dev liblzma-dev libzstd-dev autotools-dev \
    libcurl4 libcurl4-gnutls-dev libjson-c-dev automake && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /opt/torplus/tor_plus

# Building and installing
COPY --from=cache /app .
#COPY . .
RUN sh autogen.sh && \
    autoreconf -f -i && \
    ./configure  --disable-asciidoc && \
    make && \
    make install

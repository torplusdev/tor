
FROM tor_build as build

FROM debian:10
RUN echo deb http://ftp.debian.org/debian buster-backports main >> /etc/apt/sources.list.d/backports.list
RUN echo deb-src http://ftp.debian.org/debian buster-backports main >> /etc/apt/sources.list.d/backports.list
RUN apt-get update && \
    apt-get install -y libevent-dev pkg-config libssl-dev zlib1g-dev libcurl4 libcurl4-gnutls-dev \
                        libjson-c-dev expect torsocks links nginx curl netcat \
                        supervisor gettext-base net-tools jq dmidecode && \
    rm -rf /var/lib/apt/lists/*
# environment prod or stage

# ENV self_host=
# roel : hs_client client dirauth exit
ENV role=client
ARG TOR_VERSION
ENV TOR_VERSION $TOR_VERSION
ARG TOR_BUILD_HASH
ENV TOR_BUILD_HASH $TOR_BUILD_HASH
ARG TOR_BUILD_DATE
ENV TOR_BUILD_DATE $TOR_BUILD_DATE
ARG PP_ENV
ENV PP_ENV $PP_ENV

ENV wwwsite=127.0.0.1:80
# should use configuration
ENV no_conf=0
WORKDIR /opt/torplus/
RUN mkdir -p /root/tor
COPY docker/configs configs
COPY docker/tor.stage.cfg tor.stage.cfg
COPY docker/tor.prod.cfg tor.prod.cfg
COPY docker/geodata /root/geodata
COPY docker/tor-docker-entrypoint.sh /
RUN chmod 755 /tor-docker-entrypoint.sh
RUN mkdir -p /root/tor && chmod u=rwx,g=-,o=- /root/tor
COPY --from=build /usr/local/bin/tor /usr/local/bin/tor
ENTRYPOINT ["/tor-docker-entrypoint.sh"]
CMD [ "/usr/local/bin/tor", "-f", "/usr/local/etc/tor/torrc" ]

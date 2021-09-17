FROM alpine:3.1
RUN apk update
RUN apk --update add \
        gcc \
        g++ \
        libstdc++ \
        libevent-dev \
        openssl-dev \
        zlib-dev \
        json-c-dev \
        curl-dev
ENV role=client
ARG TOR_VERSION
ENV TOR_VERSION $TOR_VERSION
ARG PP_ENV
ENV PP_ENV $PP_ENV
ENV wwwsite=127.0.0.1:80
# should use configuration
ENV no_conf=0
WORKDIR /opt/paidpiper/
RUN mkdir -p /root/tor
COPY docker/configs configs
COPY docker/tor.stage.cfg tor.stage.cfg
COPY docker/tor.prod.cfg tor.prod.cfg
COPY ./geodata /root/geodata
COPY docker/tor-docker-entrypoint.sh /
RUN chmod 755 /tor-docker-entrypoint.sh
RUN mkdir -p /root/tor && chmod u=rwx,g=-,o=- /root/tor
COPY --from=build /usr/local/bin/tor /usr/local/bin/tor
COPY --from=tor_plus /usr/local/bin/tor /usr/local/bin/tor_plus

ENTRYPOINT ["/tor-docker-entrypoint.sh"]
CMD [ "/usr/local/bin/tor", "-f", "/usr/local/etc/tor/torrc" ]

FROM alpine:3.1



RUN apk update
RUN apk --update add \
        gcc \
        g++ \
        build-base \
        cmake \
        bash \
        libstdc++ \
        automake \
        autoconf \
        libevent-dev \
        openssl-dev \
        zlib-dev \
        json-c-dev \
        curl-dev
RUN apk add git cmake
COPY tor tor
#RUN apk-install make automake autoconf gcc libtool curl libevent-dev libssl1.0 musl musl-dev libgcc openssl openssl-dev openssh

# RUN git clone https://github.com/json-c/json-c.git && \
#     mkdir json-c-build && \
#     cd json-c-build && \
#     cmake ../json-c && \
#     make && \
#     make test && \
#     make USE_VALGRIND=0 test && \
#     make install

#COPY tor_plus tor_plus

# RUN cd tor/src/lib/rest && rm -rf build && mkdir -p build && cd build && cmake .. && make
# RUN cd ../tor/ && \
#     sh autogen.sh && \
#     autoreconf -f -i && \
#     ./configure  --disable-asciidoc && \
#     make && \
#     make install

#CPPFLAGS="-I/usr/local/include" LDFLAGS="-l/usr/local/lib64/libjson-c.a" &&

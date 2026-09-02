FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f

LABEL org.opencontainers.image.source="https://github.com/wzhone/tinysocks" \
      org.opencontainers.image.description="A single-port SOCKS5 and HTTP proxy server"

ENV TINYSOCKS_BIND=0.0.0.0:1080

COPY tinysocks /usr/local/bin/tinysocks

EXPOSE 1080/tcp

ENTRYPOINT ["/usr/local/bin/tinysocks"]

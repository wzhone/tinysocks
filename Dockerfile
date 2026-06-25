FROM gcr.io/distroless/cc-debian12:nonroot

LABEL org.opencontainers.image.source="https://github.com/wzhone/tinysocks" \
      org.opencontainers.image.description="A single-port SOCKS5 and HTTP proxy server"

ENV TINYSOCKS_BIND=0.0.0.0:1080

COPY tinysocks /usr/local/bin/tinysocks

EXPOSE 1080/tcp

ENTRYPOINT ["/usr/local/bin/tinysocks"]
CMD ["run"]

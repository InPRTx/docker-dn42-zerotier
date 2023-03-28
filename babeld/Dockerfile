FROM debian:bullseye-backports

COPY ./preferences /etc/apt/preferences

RUN mkdir -p /var/cache/apt/archives/partial /var/tmp/ && \
    apt-get update && apt-get install -y babeld && rm -rf /var/lib/apt/lists/*

CMD ["/usr/sbin/babeld", "-c", "/etc/babeld.conf"]
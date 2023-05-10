FROM debian:bookworm-backports

RUN mkdir -p /tmp && chmod 777 /tmp && mkdir -p /var/cache/apt/archives/partial /var/tmp/ && \
     apt-get update && \
    apt-get install -y curl cron iptables iproute2 mtr-tiny inetutils-ping dnsutils net-tools bird2 tcpdump procps htop gnupg babeld python3-psutil python3-requests python3-yaml&&  rm -rf /var/lib/apt/lists/*

RUN mkdir -p /var/cache/apt/archives/partial /var/tmp/ && \
    apt-get update && apt-get install -y babeld && rm -rf /var/lib/apt/lists/*

COPY ./enterpoint.sh /enterpoint.sh

CMD ["/enterpoint.sh"]
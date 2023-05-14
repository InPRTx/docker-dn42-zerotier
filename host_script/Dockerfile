FROM debian:bookworm-backports

RUN mkdir -p /tmp && chmod 777 /tmp && mkdir -p /var/cache/apt/archives/partial /var/tmp/ && \
     apt-get update && \
    apt-get install -y curl cron iptables iproute2 mtr-tiny inetutils-ping dnsutils net-tools wireguard-tools\
    bird2 tcpdump procps htop gnupg babeld && \
    rm -rf /var/lib/apt/lists/*

RUN apt-get update && apt-get install -y python3-psutil python3-requests python3-yaml python3-apscheduler python3-docker python3-aiohttp python3-iso3166 &&  \
    rm -rf /var/lib/apt/lists/*

RUN mkdir -p /app

COPY ./__main__.py /app/__main__.py

CMD ["python3", "-u", "/app/__main__.py"]
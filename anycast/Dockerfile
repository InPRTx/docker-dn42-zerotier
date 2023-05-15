FROM debian:bookworm-backports

RUN mkdir -p /tmp && chmod 777 /tmp && mkdir -p /var/cache/apt/archives/partial /var/tmp/ && \
     apt-get update && \
    apt-get install -y curl cron iptables iproute2 mtr-tiny inetutils-ping dnsutils net-tools wireguard-tools\
    bird2 tcpdump procps htop gnupg babeld && \
    rm -rf /var/lib/apt/lists/*

RUN apt-get update && apt-get install -y python3-psutil python3-requests python3-yaml python3-apscheduler python3-docker python3-aiohttp python3-iso3166 &&  \
    rm -rf /var/lib/apt/lists/*

RUN mkdir -p /app && mkdir -p /etc/bird/peers && mkdir -p /etc/bird/ibgps && mkdir -p /run/bird/ && \
    touch /etc/bird/roa_dn42.conf && touch /etc/bird/roa_dn42_v6.conf

RUN curl -sfSLR -o/etc/bird/roa_dn42.conf -z/etc/bird/roa_dn42.conf https://dn42.burble.com/roa/dn42_roa_bird2_4.conf &&  \
    curl -sfSLR -o/etc/bird/roa_dn42_v6.conf -z/etc/bird/roa_dn42_v6.conf https://dn42.burble.com/roa/dn42_roa_bird2_6.conf

COPY ./enterpoint.sh /enterpoint.sh

CMD ["/enterpoint.sh"]
FROM debian:bullseye-backports
#FROM ubuntu:latest

COPY ./preferences /etc/apt/preferences

RUN mkdir -p /tmp && chmod 777 /tmp && mkdir -p /var/cache/apt/archives/partial /var/tmp/ && \
    apt-get update && apt-get install -y apt-utils

RUN apt-get update && \
    apt-get install -y curl cron iptables iproute2 mtr-tiny inetutils-ping dnsutils net-tools bird2 tcpdump procps htop gnupg python3-pip gcc python3-dev
RUN pip3 install psutil ipaddress requests PyYAML

RUN mkdir -p /app && mkdir -p /etc/bird/peers && mkdir -p /etc/bird/ibgps && mkdir -p /run/bird/ && \
    touch /etc/bird/roa_dn42.conf && touch /etc/bird/roa_dn42_v6.conf

COPY ./crontab.txt /app/crontab.txt
COPY ./cron.py /app/cron.py
RUN crontab < /app/crontab.txt

COPY ./enterpoint.sh /enterpoint.sh

CMD ["/enterpoint.sh"]
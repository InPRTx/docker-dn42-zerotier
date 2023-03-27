#!/bin/bash

set -e
set -x

# 先更新一次bird的roa文件
curl -sfSLR -o/etc/bird/roa_dn42.conf -z/etc/bird/roa_dn42.conf https://dn42.burble.com/roa/dn42_roa_bird2_4.conf && curl -sfSLR -o/etc/bird/roa_dn42_v6.conf -z/etc/bird/roa_dn42_v6.conf https://dn42.burble.com/roa/dn42_roa_bird2_6.conf

python3 /app/cron.py
# 启动cron
cron
# 启动bird
bird -d

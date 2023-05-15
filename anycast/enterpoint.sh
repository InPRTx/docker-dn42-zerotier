#!/bin/bash

set -e
set -x
#ip addr add 172.23.173.173/29 dev eth0
#ip addr add 172.23.173.174/29 dev eth0
#ip addr add fdf4:56da:a360::173/64 dev eth0
#ip addr add fdf4:56da:a360::174/64 dev eth0

ip link add dn42dummy0 type dummy
ip addr add 172.23.173.173/32 dev dn42dummy0
ip addr add 172.23.173.174/32 dev dn42dummy0
ip addr add fdf4:56da:a360::173/128 dev dn42dummy0
ip addr add fdf4:56da:a360::174/128 dev dn42dummy0
ip link set dn42dummy0 up

bird -d

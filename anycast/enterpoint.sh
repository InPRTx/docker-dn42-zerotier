#!/bin/bash

set -e
set -x
ip addr add 172.23.173.173/29 dev eth0
ip addr add 172.23.173.174/29 dev eth0
ip addr add fdf4:56da:a360::173/64 dev eth0
ip addr add fdf4:56da:a360::174/64 dev eth0

bird -d

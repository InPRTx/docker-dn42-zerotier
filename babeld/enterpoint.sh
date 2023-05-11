#!/bin/bash
rm -f /var/run/babeld.pid
/usr/sbin/babeld -c /etc/babeld.conf

#!/bin/bash
git pull
docker restart docker-dn42-zerotier-host-script
docker exec -it docker-dn42-zerotier-bgp birdc c

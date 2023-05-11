import asyncio
import glob
import ipaddress
import json
import os
import socket

import aiohttp
import docker
import yaml
from apscheduler.schedulers.asyncio import AsyncIOScheduler

aio_scheduler = AsyncIOScheduler(timezone="Asia/Shanghai")
client = docker.from_env()

private_key_file = "/etc/wireguard/privatekey"
public_key_file = "/etc/wireguard/publickey"
if not os.path.exists(private_key_file):
    os.system(f"umask 077 && wg genkey | tee {private_key_file} | wg pubkey > {public_key_file}")
if not os.path.exists(public_key_file):
    os.system(f"cat {private_key_file} | wg pubkey > {public_key_file}")
prv_key = open(private_key_file, 'r').read()
pub_key = open(public_key_file, 'r').read()


def get_iface_ip(container_bgp_networks: dict, ifname: str) -> [dict, dict]:
    ifname2 = [x for x in container_bgp_networks if x['ifname'].startswith(ifname)][0]
    ipv4_list = sorted([addr['local'] for addr in ifname2['addr_info'] if addr['family'] == 'inet'])
    ipv6_list = sorted([info["local"] for info in ifname2["addr_info"] if
                        info["family"] == "inet6" and not info["local"].startswith("fe80")])
    return ipv4_list, ipv6_list


def create_dummy_ifname(zt_ipv4_list: list, zt_ipv6_list: list) -> None:
    client.containers.get('docker-dn42-zerotier-bgp').exec_run(f'ip link add dn42dummy0 type dummy')
    for zt_ipv4 in zt_ipv4_list:
        client.containers.get('docker-dn42-zerotier-bgp').exec_run(f'ip addr add {zt_ipv4}/32 dev dn42dummy0')
    for zt_ipv6 in zt_ipv6_list:
        client.containers.get('docker-dn42-zerotier-bgp').exec_run(f'ip addr add {zt_ipv6}/128 dev dn42dummy0')
    client.containers.get('docker-dn42-zerotier-bgp').exec_run('ip link set dn42dummy0 up')
    write_bird(zt_ipv4_list[0], zt_ipv6_list[0])


def write_bird(zt_ipv4: str, zt_ipv6: str):
    asn = 4242423751
    ipv4_addr_prefix = ipaddress.ip_network(
        f'{zt_ipv4}/29', False).network_address.__str__()
    ipv6_addr_prefix = ipaddress.ip_network(
        f'{zt_ipv6}/60', False).network_address.__str__()
    bird_config_text = f'''################################################
#               Variable header                #
################################################

define OWNAS =  {asn};
define OWNIP =  {zt_ipv4};
define OWNIPv6 = {zt_ipv6};
define OWNNET = {ipv4_addr_prefix}/29;
define OWNNETv6 = {ipv6_addr_prefix}/60;

################################################
#                 Header end                   #
################################################

include "/etc/bird/birds.conf";
include "/etc/bird/peers/*.conf";
include "/etc/bird/ibgps/*.conf";'''
    open('/etc/bird/bird.conf', 'w').write(bird_config_text)  # 追加直接覆盖


def write_bgp_asn(server_name: str, asn: int, host: str, prv_key: str, pub_key: str, port=23751, mtu=1400,
                  listen_port: int = None,
                  self_fe80: str = None,
                  peer_fe80: str = None):
    if not listen_port:  # 默认监听对方asn端口号
        listen_port = f'2{asn}'
    if not self_fe80:
        self_fe80 = 'fe80::3751'
    if not peer_fe80:
        peer_fe80 = f'fe80::{asn}'
    wg_config_text = f'''[Interface]
# Name: wg{asn}

PrivateKey = {prv_key}
PostUp = ip addr add dev %i {self_fe80} peer {peer_fe80}/128
ListenPort = {listen_port}
Table = off
Mtu = {mtu}

[Peer]
PublicKey = {pub_key}
Endpoint = {host}:{port}
AllowedIPs = 10.0.0.0/8, 172.20.0.0/14, 172.31.0.0/16, fd00::/8, fe00::/8'''
    with open(f'/etc/wireguard/wg{asn}{server_name}.conf', 'w') as f:
        f.write(wg_config_text)

    bird_peer_config_text = f'''
protocol bgp as424242{asn}_{server_name}_v6 from dnpeers {{
    neighbor {peer_fe80}%wg{asn}{server_name} as 424242{asn};
    ipv4 {{
        extended next hop;
    }};
}}'''
    with open(f'/etc/bird/peers/as424242{asn}-{server_name}.conf', 'w') as f:
        f.write(bird_peer_config_text)


def write_iptables(listen_port: int):
    if not any(item.get('destination_port') == str(listen_port) for item in get_prerouting_dnat_rules()):
        msg = os.popen(
            f'iptables-nft -t nat -A PREROUTING -p udp --dport {listen_port} -j DNAT --to-destination 172.30.220.202').read()
        print(msg)


def resolve_host(hostname: str, self_no_ipv4=False, self_no_ipv6=False) -> str:
    """
    解析目标域名的ip
    :param hostname:
    :param self_no_ipv4:
    :param self_no_ipv6:
    :return:
    """
    host_ipv4, host_ipv6 = None, None
    for family, _, _, _, sockaddr in socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM):
        if family == socket.AF_INET:
            host_ipv4 = sockaddr[0]
        elif family == socket.AF_INET6:
            host_ipv6 = sockaddr[0]
    if host_ipv6 and self_no_ipv6:
        return host_ipv6
    return host_ipv4


def get_prerouting_dnat_rules() -> list[dict]:
    rules = os.popen('iptables-nft -t nat -S PREROUTING').read().strip().split('\n')
    prerouting_rules = []
    for rule in rules:
        parts = rule.split()
        prerouting_rule = {'rule': parts[0]}
        for i in range(1, len(parts)):
            if parts[i] == '-p':
                prerouting_rule['protocol'] = parts[i + 1]
            elif parts[i] == '-d':
                prerouting_rule['destination'] = parts[i + 1]
            elif parts[i] == '--dport':
                prerouting_rule['destination_port'] = parts[i + 1]
            elif parts[i] == '-j':
                prerouting_rule['target'] = parts[i + 1]
        if 'target' in prerouting_rule and prerouting_rule['target'] == 'DNAT':
            prerouting_rules.append(prerouting_rule)
    return prerouting_rules


async def update_dn42_data(bird_c=True) -> None:
    print('开始更新配置')
    async with aiohttp.ClientSession() as s:
        r4 = await s.get('https://dn42.burble.com/roa/dn42_roa_bird2_4.conf')
        r6 = await s.get('https://dn42.burble.com/roa/dn42_roa_bird2_6.conf')
        rs = await s.get('https://public.23751.net/dn42/info.yml')
    if r4.status != 200 or r6.status != 200 or rs.status != 200:
        return
    container_bgp_networks = json.loads(
        client.containers.get('docker-dn42-zerotier-zerotier').exec_run('ip --json address show').output.decode(
            'utf-8'))
    zt_ipv4_list, zt_ipv6_list = get_iface_ip(container_bgp_networks, 'zt')
    server_name = None
    with open('/etc/bird/roa_dn42_v4.conf', 'w') as f:
        f.write(await r4.text())
    with open('/etc/bird/roa_dn42_v6.conf', 'w') as f:
        f.write(await r6.text())
    config = yaml.full_load(await rs.text())
    for ibgps_file in glob.glob('/etc/bird/ibgps/*.conf'):
        os.remove(ibgps_file)  # TODO 升级为删除旧版本的配置文件
    for name, b in config['servers'].items():
        if b['ipv4'] in zt_ipv4_list:
            server_name = name
            continue
        if 'peer' in b and not b['peer']:
            continue
        ibgp_text = f'protocol bgp ibgp_{name} from IBGP {{\nneighbor {b["ipv6"]} as OWNAS;}}'
        with open(f'/etc/bird/ibgps/{name}.conf', 'w') as f:
            f.write(ibgp_text)
    if not server_name:  # 配置文件不存在本机就不配置
        return
    no_ipv4 = config['servers'][server_name]['no_ipv4'] if 'no_ipv4' in config['servers'][server_name] else False
    no_ipv6 = config['servers'][server_name]['no_ipv6'] if 'no_ipv6' in config['servers'][server_name] else False
    for wg in config['servers'][server_name]['wg']:  # 生成wg隧道配置，接口不存在则配置
        host = resolve_host(wg['host'], no_ipv4, no_ipv6)
        listen_port = wg['listen_port'] if 'listen_port' in wg else int(f"2{wg['asn']}")
        port = wg['port'] if 'port' in wg else 23751
        mtu = wg['mtu'] if 'mtu' in wg else 1400
        self_fe80 = wg['self_fe80'] if 'self_fe80' in wg else f"fe80::3751"
        peer_fe80 = wg['peer_fe80'] if 'peer_fe80' in wg else f"fe80::{wg['asn']}"
        write_bgp_asn(wg['name'], wg['asn'], host, prv_key, wg['pub_key'], port, mtu, listen_port, self_fe80, peer_fe80)
        if not any(iface.get('ifname') == f"wg{wg['asn']}{server_name}" for iface in container_bgp_networks):
            print('启动接口', f"wg-quick up wg{wg['asn']}{server_name}")
            client.containers.get('docker-dn42-zerotier-bgp').exec_run(f"wg-quick up wg{wg['asn']}{server_name}")
            write_iptables(listen_port)
    if bird_c:
        client.containers.get('docker-dn42-zerotier-bgp').exec_run('birdc c')


async def job1() -> None:
    if not client.containers.get('docker-dn42-zerotier-babeld') \
            or not client.containers.get('docker-dn42-zerotier-host-script') \
            or not client.containers.get('docker-dn42-zerotier-zerotier'):
        return  # 容器未创建则退出
    container_bgp_networks = json.loads(
        client.containers.get('docker-dn42-zerotier-zerotier').exec_run('ip --json address show').output.decode(
            'utf-8'))
    if any(iface.get('ifname') == 'dn42dummy0' for iface in container_bgp_networks):
        # 判断 dummy 网卡 是否跟 dn42 网卡地址一样，删除网卡
        zt_ipv4_list, zt_ipv6_list = get_iface_ip(container_bgp_networks, 'zt')
        dy_ipv4_list, dy_ipv6_list = get_iface_ip(container_bgp_networks, 'dn42dummy0')

        if zt_ipv4_list != dy_ipv4_list or zt_ipv6_list != dy_ipv6_list:
            client.containers.get('docker-dn42-zerotier-zerotier').exec_run(f'ip link del dn42dummy0')
            create_dummy_ifname(zt_ipv4_list, zt_ipv6_list)
    else:
        zt_ipv4_list, zt_ipv6_list = get_iface_ip(container_bgp_networks, 'zt')
        create_dummy_ifname(zt_ipv4_list, zt_ipv6_list)


async def main():
    print('server wg pubkey:', pub_key)
    await update_dn42_data(False)
    await job1()
    aio_scheduler.add_job(job1, 'interval', minutes=1)
    aio_scheduler.add_job(update_dn42_data, 'interval', minutes=15)
    aio_scheduler.start()
    while True:
        await asyncio.sleep(60)


if __name__ == '__main__':
    asyncio.run(main())

import ipaddress
import re

import psutil
import requests
import yaml
from psutil._common import snicaddr

s = requests.Session()


class CUSTONSET:
    asn = 4242423751
    min_ipv4_subnet = 29
    min_ipv6_subnet = 60


class DN42RULE:
    ipv4_netmask = ipaddress.ip_network('172.20.0.0/14')
    ipv6_netmask = ipaddress.ip_network('fd00::/8')


class ZTDN42INTERFACE:
    ipv4_addr: str = None
    ipv4_addr_prefix: ipaddress.IPv4Network = None
    ipv6_addr: str = None
    ipv6_addr_prefix: ipaddress.IPv6Network = None
    ipv6_fe80_addr: ipaddress.IPv6Network = None
    mac: str = None
    is_dn42 = False

    def __out_bird(self):
        self.bird_config_text = f'''################################################
#               Variable header                #
################################################

define OWNAS =  {CUSTONSET.asn};
define OWNIP =  {self.ipv4_addr};
define OWNIPv6 = {self.ipv6_addr};
define OWNNET = {self.ipv4_addr_prefix};
define OWNNETv6 = {self.ipv6_addr_prefix};

################################################
#                 Header end                   #
################################################

include "/etc/bird/birds.conf";
include "/etc/bird/peers/*.conf";
include "/etc/bird/ibgps/*.conf";'''

    def write_bird_conf(self) -> bool:
        self.__out_bird()
        open('/etc/bird/bird.conf', 'w').write(self.bird_config_text)  # 追加直接覆盖
        return True

    def write_ibgp(self) -> bool:
        r = s.get('https://public.23751.net/dn42/info.yml')
        if r.status_code // 200 != 1:
            return False
        self.config_yaml = yaml.full_load(r.text)
        for name, b in self.config_yaml['ibgp'].items():
            if b['ipv4'] == self.ipv4_addr:  # 跳过自己
                continue
            ibgp_text = f'''protocol bgp ibgp_{name} from IBGP {{
neighbor {b['ipv6']} as OWNAS;
}}'''
            open(f'/etc/bird/ibgps/{name}.conf', 'w').write(ibgp_text)


def is_dn42_interface(nic_interface: list[snicaddr]) -> ZTDN42INTERFACE:
    zt_dn42_interface = ZTDN42INTERFACE()
    for addr in nic_interface:
        if '-' in addr.address or re.match(r'([0-9a-f]{2}:){5}[0-9a-f]{2}', addr.address.lower()):  # 这是mac地址
            zt_dn42_interface.mac = addr.address
            continue
        ip_addr = ipaddress.ip_network(addr.address)
        if DN42RULE.ipv4_netmask.overlaps(ip_addr):
            zt_dn42_interface.ipv4_addr = ip_addr.network_address
            zt_dn42_interface.ipv4_addr_prefix = ipaddress.ip_network(
                f'{ip_addr.network_address}/{CUSTONSET.min_ipv4_subnet}', False)
        elif DN42RULE.ipv6_netmask.overlaps(ip_addr):
            zt_dn42_interface.ipv6_addr = ip_addr.network_address
            zt_dn42_interface.ipv6_addr_prefix = ipaddress.ip_network(
                f'{ip_addr.network_address}/{CUSTONSET.min_ipv6_subnet}', False)
        elif ip_addr.version == 6 and addr.address.startswith('fe80'):
            zt_dn42_interface.ipv6_fe80_addr = ip_addr
    if zt_dn42_interface.ipv4_addr and zt_dn42_interface.ipv6_addr and zt_dn42_interface.ipv6_fe80_addr:
        zt_dn42_interface.is_dn42 = True
    return zt_dn42_interface


def get_zt_interface():
    for nic_name, nic_interface in psutil.net_if_addrs().items():
        if ('ZeroTier One' in nic_name or 'zt' in nic_name) and is_dn42_interface(nic_interface).is_dn42:
            # print(is_dn42_interface(nic_interface).is_dn42)
            zt_dn42_interface = is_dn42_interface(nic_interface)
            zt_dn42_interface.write_bird_conf()
            zt_dn42_interface.write_ibgp()
            break
            # print(nic_name, nic_interface[2].address)


if __name__ == '__main__':
    get_zt_interface()

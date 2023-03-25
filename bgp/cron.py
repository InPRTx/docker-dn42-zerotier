import ipaddress

import psutil
from psutil._common import snicaddr


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

    def out_bird(self):
        config_text = f'''################################################
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
        print(config_text)


def is_dn42_interface(nic_interface: list[snicaddr]) -> ZTDN42INTERFACE:
    zt_dn42_interface = ZTDN42INTERFACE()
    for addr in nic_interface:
        if '-' in addr.address:  # 这是mac地址
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
            zt_dn42_interface.out_bird()
            # print(nic_name, nic_interface[2].address)


if __name__ == '__main__':
    get_zt_interface()

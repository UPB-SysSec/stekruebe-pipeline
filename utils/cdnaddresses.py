from ipaddress import *
import json

def is_network_ip(ip, v4network, v6network):
    # TODO better do regex magic
    if "." in ip:
        ip = IPv4Address(ip)
        network = v4network
    else:
        ip = IPv6Address(ip)
        network = v6network
    for x in network:
        if ip in x:
            return True
    return False


# https://www.cloudflare.com/ips/ Accessed: 2024-12-13
cloudflare_network_v4 = [
    IPv4Network(x)
    for x in [
        "173.245.48.0/20",
        "103.21.244.0/22",
        "103.22.200.0/22",
        "103.31.4.0/22",
        "141.101.64.0/18",
        "108.162.192.0/18",
        "190.93.240.0/20",
        "188.114.96.0/20",
        "197.234.240.0/22",
        "198.41.128.0/17",
        "162.158.0.0/15",
        "104.16.0.0/13",
        "104.24.0.0/14",
        "172.64.0.0/13",
        "131.0.72.0/22",
    ]
]
cloudflare_network_v6 = [
    IPv6Network(x)
    for x in [
        "2400:cb00::/32",
        "2606:4700::/32",
        "2803:f800::/32",
        "2405:b500::/32",
        "2405:8100::/32",
        "2a06:98c0::/29",
        "2c0f:f248::/32",
    ]
]


def is_cloudflare_ip(ip):
    return is_network_ip(ip, cloudflare_network_v4, cloudflare_network_v6)


# https://www.fastly.com/documentation/reference/api/utils/public-ip-list/ Accessed: 2024-12-13
fastly_network_v4 = [
    IPv4Network(x)
    for x in [
        "23.235.32.0/20",
        "43.249.72.0/22",
        "103.244.50.0/24",
        "103.245.222.0/23",
        "103.245.224.0/24",
        "104.156.80.0/20",
        "140.248.64.0/18",
        "140.248.128.0/17",
        "146.75.0.0/17",
        "151.101.0.0/16",
        "157.52.64.0/18",
        "167.82.0.0/17",
        "167.82.128.0/20",
        "167.82.160.0/20",
        "167.82.224.0/20",
        "172.111.64.0/18",
        "185.31.16.0/22",
        "199.27.72.0/21",
        "199.232.0.0/16",
    ]
]
fastly_network_v6 = [IPv6Network(x) for x in ["2a04:4e40::/32", "2a04:4e42::/32"]]


def is_fastly_ip(ip):
    return is_network_ip(ip, fastly_network_v4, fastly_network_v6)


# File from https://github.com/SecOps-Institute/Akamai-ASN-and-IPs-List/blob/master/akamai_ip_cidr_blocks_raw.lst, Replace if you find anything better. Downloaded: 2024-12-13
with open("ip_lists/akamai_ip_cidr_blocks_raw.lst") as f:
    akamai_network_v4 = [IPv4Network(x.rstrip()) for x in f.readlines()]
# https://cidr-aggregator.pages.dev/
with open("ip_lists/akamai_ipv6_list.lst") as f:
    akamai_network_v6 = [IPv6Network(x.rstrip()) for x in f.readlines()]


def is_akamai_ip(ip):
    return is_network_ip(ip, akamai_network_v4, akamai_network_v6)


amazon_network_ipv4 = []
amazon_network_ipv6 = []
with open("ip_lists/amazon.json") as ips:
    jsonlist = json.load(ips)
    for x in jsonlist.get("prefixes"):
        if x.get("ip_prefix") is not None:
            amazon_network_ipv4.append(IPv4Network(x.get("ip_prefix")))
    for x in jsonlist.get("ipv6_prefixes"):
        if x.get("ipv6_prefix") is not None:
            amazon_network_ipv6.append(IPv6Network(x.get("ipv6_prefix")))

def is_amazon_ip(ip):
    return is_network_ip(ip, amazon_network_ipv4, amazon_network_ipv6)


google_network_ipv4 = []
google_network_ipv6 = []
with open("ip_lists/google_ips.json") as ips:
    ipdata = json.load(ips).get("prefixes")
    for x in ipdata:
        if x.get("ipv4Prefix") is not None:
            google_network_ipv4.append(IPv4Network(x.get("ipv4Prefix")))
        if x.get("ipv6Prefix") is not None:
            google_network_ipv6.append(IPv6Network(x.get("ipv6Prefix")))


def is_google_ip(ip):
    return is_network_ip(ip, google_network_ipv4, google_network_ipv6)

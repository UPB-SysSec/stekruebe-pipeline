from ipaddress import IPv4Address, IPv6Address, ip_address, IPv4Network, IPv6Network, ip_network
import json
from dataclasses import dataclass
from pathlib import Path

__ASN_IP_DIR = Path(__file__).parent.parent / "asn-ip" / "as"


@dataclass(frozen=True, slots=True)
class AS:
    number: int
    handle: str
    description: str
    ipv4s: set[IPv4Network]
    ipv6s: set[IPv6Network]

    def __contains__(self, ip: IPv4Address | IPv6Address):
        if isinstance(ip, IPv4Address):
            return any(ip in net for net in self.ipv4s)
        elif isinstance(ip, IPv6Address):
            return any(ip in net for net in self.ipv6s)
        else:
            raise TypeError(f"Expected IPv4Address or IPv6Address, got {type(ip)}")

    def __str__(self):
        return f"AS{self.number} ({self.handle} | {self.description})"

    def __repr__(self):
        return f"<AS({self.number}, {self.handle}, {self.description}, {len(self.ipv4s)}, {len(self.ipv6s)})>"


_ALL_ASES = {}


def _load_as(folder: Path):
    with (folder / "aggregated.json").open() as f:
        data = json.load(f)
        return AS(
            data["asn"],
            data.get("handle", f"AS{data['asn']}"),
            data.get("description", "---"),
            {ip_network(net) for net in data["subnets"]["ipv4"]},
            {ip_network(net) for net in data["subnets"]["ipv6"]},
        )


def _load_all(folder: Path = __ASN_IP_DIR):
    for asn in folder.iterdir():
        if asn.is_dir():
            as_ = _load_as(asn)
            assert as_.number == int(asn.name)
            _ALL_ASES[as_.number] = as_


def lookup(ip: str | IPv4Address | IPv6Address):
    if isinstance(ip, str):
        ip = ip_address(ip)
    for as_ in _ALL_ASES.values():
        if ip in as_:
            return as_


def lookup_multi(ip: str | IPv4Address | IPv6Address):
    if isinstance(ip, str):
        ip = ip_address(ip)
    for as_ in _ALL_ASES.values():
        if ip in as_:
            yield as_


_load_all()
if __name__ == "__main__":
    import time

    class MeasureTime:
        def __init__(self, name):
            self.name = name

        def __enter__(self):
            self.start = time.time()

        def __exit__(self, exc_type, exc_val, exc_tb):
            print(f"{self.name}: {time.time() - self.start}")

    lookup_target = "1.1.1.1"
    lookup_target = "23.227.38.74"

    # with MeasureTime("load"):
    print(lookup_target)
    with MeasureTime("lookup"):
        print(lookup(lookup_target))
    with MeasureTime("lookup_multi"):
        print(list(lookup_multi(lookup_target)))

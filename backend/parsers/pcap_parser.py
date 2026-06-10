"""PCAP parsing using Scapy."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterator

from scapy.all import PcapReader  # type: ignore
from scapy.layers.dns import DNS, DNSQR  # type: ignore
from scapy.layers.inet import ICMP, IP, TCP, UDP  # type: ignore
from scapy.layers.inet6 import IPv6  # type: ignore
from scapy.layers.l2 import ARP, Ether  # type: ignore


@dataclass
class ParsedPacket:
    ts: float
    src_ip: str | None
    dst_ip: str | None
    src_port: int | None
    dst_port: int | None
    protocol: str
    length: int
    tcp_flags: str | None
    info: dict


_TCP_FLAG_NAMES = [
    (0x01, "F"), (0x02, "S"), (0x04, "R"),
    (0x08, "P"), (0x10, "A"), (0x20, "U"),
]


def _fmt_flags(flags: int) -> str:
    return "".join(name for bit, name in _TCP_FLAG_NAMES if flags & bit) or "-"


def parse_pcap(path: str) -> Iterator[ParsedPacket]:
    """Yield ParsedPacket objects for each frame in the PCAP at *path*."""
    with PcapReader(path) as reader:
        for pkt in reader:
            yield _parse_packet(pkt)


def _parse_packet(pkt) -> ParsedPacket:
    ts = float(getattr(pkt, "time", 0.0))
    length = len(pkt)
    src_ip = dst_ip = None
    src_port = dst_port = None
    protocol = "OTHER"
    tcp_flags = None
    info: dict = {}

    if IP in pkt:
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        protocol = "IP"
    elif IPv6 in pkt:
        src_ip = pkt[IPv6].src
        dst_ip = pkt[IPv6].dst
        protocol = "IPv6"
    elif ARP in pkt:
        protocol = "ARP"
        arp = pkt[ARP]
        src_ip = arp.psrc
        dst_ip = arp.pdst
        info = {
            "op": int(arp.op),
            "hwsrc": arp.hwsrc,
            "hwdst": arp.hwdst,
        }
    elif Ether in pkt:
        protocol = "ETH"

    if TCP in pkt:
        protocol = "TCP"
        t = pkt[TCP]
        src_port = int(t.sport)
        dst_port = int(t.dport)
        tcp_flags = _fmt_flags(int(t.flags))
    elif UDP in pkt:
        protocol = "UDP"
        u = pkt[UDP]
        src_port = int(u.sport)
        dst_port = int(u.dport)
        if DNS in pkt and pkt[DNS].qd is not None:
            try:
                qname = pkt[DNSQR].qname.decode(errors="replace").rstrip(".")
            except Exception:
                qname = ""
            info["dns_qname"] = qname
            info["dns_qtype"] = int(pkt[DNSQR].qtype)
            protocol = "DNS"
    elif ICMP in pkt:
        protocol = "ICMP"
        info["icmp_type"] = int(pkt[ICMP].type)

    return ParsedPacket(
        ts=ts,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        length=length,
        tcp_flags=tcp_flags,
        info=info,
    )

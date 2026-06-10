"""Unit tests for detection logic using synthetic ParsedPacket inputs."""
from __future__ import annotations

import time

from backend.detectors.arp_spoofing import ArpSpoofingDetector
from backend.detectors.beaconing import BeaconingDetector
from backend.detectors.brute_force import BruteForceDetector
from backend.detectors.dns_tunneling import DnsTunnelingDetector
from backend.detectors.port_scan import PortScanDetector
from backend.detectors.syn_flood import SynFloodDetector
from backend.parsers.pcap_parser import ParsedPacket


def _syn(ts: float, src: str, dst: str, dport: int) -> ParsedPacket:
    return ParsedPacket(
        ts=ts, src_ip=src, dst_ip=dst, src_port=12345, dst_port=dport,
        protocol="TCP", length=60, tcp_flags="S", info={},
    )


def test_port_scan_detects_many_unique_ports():
    base = 1_000_000.0
    packets = [_syn(base + i * 0.1, "10.0.0.5", "10.0.0.10", 1000 + i) for i in range(30)]
    alerts = PortScanDetector().detect(packets)
    assert any(a.category == "port_scan" for a in alerts)


def test_syn_flood_triggers_above_threshold():
    base = 1_000_000.0
    # 600 SYNs across 5 seconds -> 120 syn/s, default rate 100
    packets = [_syn(base + i * (5 / 600), "10.0.0.5", "10.0.0.99", 80) for i in range(600)]
    alerts = SynFloodDetector().detect(packets)
    assert any(a.category == "syn_flood" for a in alerts)


def test_brute_force_ssh():
    base = 1_000_000.0
    packets = [_syn(base + i, "10.0.0.5", "10.0.0.20", 22) for i in range(20)]
    alerts = BruteForceDetector().detect(packets)
    assert any(a.category == "brute_force" for a in alerts)


def test_beaconing_periodic_low_jitter():
    base = 1_000_000.0
    # Use a non-standard port — beaconing on 80/443/etc is filtered out by
    # default to suppress false positives from API polling.
    packets = [_syn(base + i * 30.0, "10.0.0.5", "1.2.3.4", 8443) for i in range(15)]
    alerts = BeaconingDetector().detect(packets)
    assert any(a.category == "beaconing" for a in alerts)


def test_beaconing_skips_standard_ports():
    base = 1_000_000.0
    # Same periodic SYNs but to port 443 — should NOT alert by default.
    packets = [_syn(base + i * 30.0, "10.0.0.5", "1.2.3.4", 443) for i in range(15)]
    alerts = BeaconingDetector().detect(packets)
    assert not any(a.category == "beaconing" for a in alerts)


def test_dns_tunneling_long_queries():
    base = 1_000_000.0
    long_label = "a" * 60 + ".example.com"
    packets = [
        ParsedPacket(
            ts=base + i, src_ip="10.0.0.5", dst_ip="8.8.8.8",
            src_port=33333, dst_port=53, protocol="DNS", length=120,
            tcp_flags=None, info={"dns_qname": long_label, "dns_qtype": 1},
        )
        for i in range(10)
    ]
    alerts = DnsTunnelingDetector().detect(packets)
    assert any(a.category == "dns_tunneling" for a in alerts)


def test_arp_spoofing_multiple_macs():
    base = time.time()
    packets = [
        ParsedPacket(
            ts=base, src_ip="10.0.0.1", dst_ip="10.0.0.5",
            src_port=None, dst_port=None, protocol="ARP", length=42,
            tcp_flags=None, info={"op": 2, "hwsrc": "aa:bb:cc:dd:ee:01", "hwdst": "ff:ff:ff:ff:ff:ff"},
        ),
        ParsedPacket(
            ts=base + 1, src_ip="10.0.0.1", dst_ip="10.0.0.6",
            src_port=None, dst_port=None, protocol="ARP", length=42,
            tcp_flags=None, info={"op": 2, "hwsrc": "aa:bb:cc:dd:ee:02", "hwdst": "ff:ff:ff:ff:ff:ff"},
        ),
    ]
    alerts = ArpSpoofingDetector().detect(packets)
    assert any(a.category == "arp_spoofing" for a in alerts)

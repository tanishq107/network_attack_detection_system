"""Detector registry."""
from __future__ import annotations

from .arp_spoofing import ArpSpoofingDetector
from .base import DetectionAlert
from .beaconing import BeaconingDetector
from .brute_force import BruteForceDetector
from .dns_tunneling import DnsTunnelingDetector
from .malware_traffic import MalwareTrafficDetector
from .mitre_map import MITRE_MAP
from .port_scan import PortScanDetector
from .syn_flood import SynFloodDetector


def all_detectors():
    return [
        PortScanDetector(),
        SynFloodDetector(),
        DnsTunnelingDetector(),
        BruteForceDetector(),
        BeaconingDetector(),
        ArpSpoofingDetector(),
        MalwareTrafficDetector(),
    ]


def run_all(packets) -> list[DetectionAlert]:
    alerts: list[DetectionAlert] = []
    for det in all_detectors():
        try:
            alerts.extend(det.detect(packets))
        except Exception as exc:  # pragma: no cover - defensive
            import logging

            logging.exception("Detector %s failed: %s", det.name, exc)
    return alerts


__all__ = [
    "DetectionAlert",
    "MITRE_MAP",
    "all_detectors",
    "run_all",
]

"""ARP spoofing / cache poisoning detector."""
from __future__ import annotations

from collections import defaultdict

from backend.parsers import ParsedPacket

from .base import DetectionAlert


class ArpSpoofingDetector:
    name = "arp_spoofing"

    def detect(self, packets: list[ParsedPacket]):
        # ip -> set of MACs seen claiming it
        ip_to_macs: dict[str, set[str]] = defaultdict(set)
        first_ts: dict[str, float] = {}
        for p in packets:
            if p.protocol != "ARP" or not p.info:
                continue
            # Only ARP replies (op=2) are reliable for binding claims.
            if p.info.get("op") != 2:
                continue
            ip = p.src_ip
            mac = p.info.get("hwsrc")
            if not ip or not mac or mac == "00:00:00:00:00:00":
                continue
            ip_to_macs[ip].add(mac)
            first_ts.setdefault(ip, p.ts)

        alerts: list[DetectionAlert] = []
        for ip, macs in ip_to_macs.items():
            if len(macs) > 1:
                alerts.append(
                    DetectionAlert.build(
                        category=self.name,
                        ts=first_ts.get(ip, 0.0),
                        severity="high",
                        title=f"ARP spoofing on {ip}",
                        description=(
                            f"IP {ip} was advertised by {len(macs)} different MAC addresses."
                        ),
                        src_ip=ip,
                        evidence={"ip": ip, "macs": sorted(macs)},
                    )
                )
        return alerts

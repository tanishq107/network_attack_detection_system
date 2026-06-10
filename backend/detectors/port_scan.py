"""Horizontal/vertical port scan detector."""
from __future__ import annotations

from collections import defaultdict

from backend.config import PORT_SCAN_UNIQUE_PORTS, PORT_SCAN_WINDOW_SEC
from backend.parsers import ParsedPacket

from .base import DetectionAlert


class PortScanDetector:
    name = "port_scan"

    def detect(self, packets: list[ParsedPacket]):
        # src_ip -> list[(ts, dst_ip, dst_port)] for SYN-only packets
        events: dict[str, list[tuple[float, str, int]]] = defaultdict(list)
        for p in packets:
            if p.protocol != "TCP" or not p.src_ip or not p.dst_ip or p.dst_port is None:
                continue
            # Classic SYN scan: SYN set, ACK not set.
            if p.tcp_flags and "S" in p.tcp_flags and "A" not in p.tcp_flags:
                events[p.src_ip].append((p.ts, p.dst_ip, p.dst_port))

        alerts: list[DetectionAlert] = []
        for src, entries in events.items():
            entries.sort()
            i = 0
            for j in range(len(entries)):
                while entries[j][0] - entries[i][0] > PORT_SCAN_WINDOW_SEC:
                    i += 1
                window = entries[i : j + 1]
                unique_ports = {(d, p) for _, d, p in window}
                if len(unique_ports) >= PORT_SCAN_UNIQUE_PORTS:
                    dst_ips = sorted({d for d, _ in unique_ports})
                    alerts.append(
                        DetectionAlert.build(
                            category=self.name,
                            ts=window[0][0],
                            severity="medium",
                            title=f"Port scan from {src}",
                            description=(
                                f"{src} contacted {len(unique_ports)} unique "
                                f"(dst,port) pairs within {PORT_SCAN_WINDOW_SEC}s."
                            ),
                            src_ip=src,
                            dst_ip=dst_ips[0] if len(dst_ips) == 1 else None,
                            evidence={
                                "unique_targets": len(unique_ports),
                                "window_sec": PORT_SCAN_WINDOW_SEC,
                                "sample_targets": list(sorted(unique_ports))[:20],
                            },
                        )
                    )
                    break  # one alert per source per pcap
        return alerts

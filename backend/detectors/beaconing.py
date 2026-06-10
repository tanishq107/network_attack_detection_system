"""C2 beaconing detector (periodic outbound connections, low jitter)."""
from __future__ import annotations

import statistics
from collections import defaultdict

from backend.config import (
    BEACON_INCLUDE_STANDARD,
    BEACON_JITTER_RATIO,
    BEACON_MIN_CONNECTIONS,
    BEACON_STANDARD_PORTS,
)
from backend.parsers import ParsedPacket

from .base import DetectionAlert


class BeaconingDetector:
    name = "beaconing"

    def detect(self, packets: list[ParsedPacket]):
        # (src, dst, dst_port) -> list[ts] of new outbound connections (SYN-only)
        events: dict[tuple[str, str, int], list[float]] = defaultdict(list)
        for p in packets:
            if (
                p.protocol == "TCP"
                and p.src_ip
                and p.dst_ip
                and p.dst_port is not None
                and p.tcp_flags
                and "S" in p.tcp_flags
                and "A" not in p.tcp_flags
            ):
                # Standard service ports are heavy false-positive sources
                # (HTTPS API polling, mail check loops, DB pools, RDP). Only
                # flag periodic SYNs to non-standard ports unless explicitly
                # opted back in via NADE_BEACON_INCLUDE_STANDARD=1.
                if (
                    not BEACON_INCLUDE_STANDARD
                    and p.dst_port in BEACON_STANDARD_PORTS
                ):
                    continue
                events[(p.src_ip, p.dst_ip, p.dst_port)].append(p.ts)

        alerts: list[DetectionAlert] = []
        for (src, dst, port), ts_list in events.items():
            if len(ts_list) < BEACON_MIN_CONNECTIONS:
                continue
            ts_list.sort()
            intervals = [b - a for a, b in zip(ts_list, ts_list[1:]) if b - a > 0]
            if len(intervals) < 4:
                continue
            mean = statistics.mean(intervals)
            if mean <= 0:
                continue
            stdev = statistics.pstdev(intervals)
            jitter = stdev / mean
            if jitter <= BEACON_JITTER_RATIO and mean >= 1.0:
                alerts.append(
                    DetectionAlert.build(
                        category=self.name,
                        ts=ts_list[0],
                        severity="medium",
                        title=f"Beaconing {src} -> {dst}:{port}",
                        description=(
                            f"{len(ts_list)} periodic connections every ~{mean:.1f}s "
                            f"(jitter {jitter:.2f})."
                        ),
                        src_ip=src,
                        dst_ip=dst,
                        evidence={
                            "interval_mean_sec": round(mean, 2),
                            "jitter_ratio": round(jitter, 3),
                            "connections": len(ts_list),
                            "port": port,
                        },
                    )
                )
        return alerts

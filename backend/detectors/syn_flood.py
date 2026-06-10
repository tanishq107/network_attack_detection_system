"""SYN flood detector."""
from __future__ import annotations

from collections import defaultdict

from backend.config import SYN_FLOOD_RATE, SYN_FLOOD_WINDOW_SEC
from backend.parsers import ParsedPacket

from .base import DetectionAlert


class SynFloodDetector:
    name = "syn_flood"

    def detect(self, packets: list[ParsedPacket]):
        # dst_ip -> list[ts] of SYN-only packets
        events: dict[str, list[float]] = defaultdict(list)
        for p in packets:
            if p.protocol != "TCP" or not p.dst_ip:
                continue
            if p.tcp_flags and "S" in p.tcp_flags and "A" not in p.tcp_flags:
                events[p.dst_ip].append(p.ts)

        threshold = SYN_FLOOD_RATE * SYN_FLOOD_WINDOW_SEC
        alerts: list[DetectionAlert] = []
        for dst, ts_list in events.items():
            ts_list.sort()
            i = 0
            peak = 0
            peak_start = None
            for j in range(len(ts_list)):
                while ts_list[j] - ts_list[i] > SYN_FLOOD_WINDOW_SEC:
                    i += 1
                count = j - i + 1
                if count > peak:
                    peak = count
                    peak_start = ts_list[i]
            if peak >= threshold and peak_start is not None:
                alerts.append(
                    DetectionAlert.build(
                        category=self.name,
                        ts=peak_start,
                        severity="high",
                        title=f"Possible SYN flood against {dst}",
                        description=(
                            f"{peak} SYN packets in {SYN_FLOOD_WINDOW_SEC}s "
                            f"(threshold {threshold})."
                        ),
                        dst_ip=dst,
                        evidence={
                            "syn_count": peak,
                            "window_sec": SYN_FLOOD_WINDOW_SEC,
                            "threshold": threshold,
                        },
                    )
                )
        return alerts

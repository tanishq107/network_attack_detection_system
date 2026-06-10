"""Brute-force login detector (SSH/FTP/RDP/SMB heuristic)."""
from __future__ import annotations

from collections import defaultdict

from backend.config import BRUTE_FORCE_ATTEMPTS, BRUTE_FORCE_WINDOW_SEC
from backend.parsers import ParsedPacket

from .base import DetectionAlert

LOGIN_PORTS = {22: "SSH", 21: "FTP", 23: "Telnet", 3389: "RDP", 445: "SMB", 1433: "MSSQL", 3306: "MySQL"}


class BruteForceDetector:
    name = "brute_force"

    def detect(self, packets: list[ParsedPacket]):
        # (src, dst, dst_port) -> list[ts] of SYN attempts
        events: dict[tuple[str, str, int], list[float]] = defaultdict(list)
        for p in packets:
            if (
                p.protocol == "TCP"
                and p.src_ip
                and p.dst_ip
                and p.dst_port in LOGIN_PORTS
                and p.tcp_flags
                and "S" in p.tcp_flags
                and "A" not in p.tcp_flags
            ):
                events[(p.src_ip, p.dst_ip, p.dst_port)].append(p.ts)

        alerts: list[DetectionAlert] = []
        for (src, dst, port), ts_list in events.items():
            ts_list.sort()
            i = 0
            peak = 0
            peak_start = None
            for j in range(len(ts_list)):
                while ts_list[j] - ts_list[i] > BRUTE_FORCE_WINDOW_SEC:
                    i += 1
                count = j - i + 1
                if count > peak:
                    peak = count
                    peak_start = ts_list[i]
            if peak >= BRUTE_FORCE_ATTEMPTS and peak_start is not None:
                svc = LOGIN_PORTS[port]
                alerts.append(
                    DetectionAlert.build(
                        category=self.name,
                        ts=peak_start,
                        severity="high",
                        title=f"Brute force on {svc} {dst}:{port} from {src}",
                        description=(
                            f"{peak} {svc} connection attempts from {src} to "
                            f"{dst}:{port} within {BRUTE_FORCE_WINDOW_SEC}s."
                        ),
                        src_ip=src,
                        dst_ip=dst,
                        evidence={
                            "service": svc,
                            "attempts": peak,
                            "window_sec": BRUTE_FORCE_WINDOW_SEC,
                            "port": port,
                        },
                    )
                )
        return alerts

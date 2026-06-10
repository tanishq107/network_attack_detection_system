"""DNS tunneling / DGA-style detection (heuristic)."""
from __future__ import annotations

from collections import defaultdict

from backend.config import DNS_TUNNEL_QNAME_LEN, DNS_TUNNEL_QPS
from backend.parsers import ParsedPacket

from .base import DetectionAlert


class DnsTunnelingDetector:
    name = "dns_tunneling"

    def detect(self, packets: list[ParsedPacket]):
        per_src: dict[str, list[ParsedPacket]] = defaultdict(list)
        for p in packets:
            if p.protocol == "DNS" and p.src_ip and p.info.get("dns_qname"):
                per_src[p.src_ip].append(p)

        alerts: list[DetectionAlert] = []
        for src, plist in per_src.items():
            long_q = [p for p in plist if len(p.info.get("dns_qname", "")) >= DNS_TUNNEL_QNAME_LEN]
            duration = max(1.0, plist[-1].ts - plist[0].ts) if len(plist) > 1 else 1.0
            qps = len(plist) / duration
            if len(long_q) >= 5 or qps >= DNS_TUNNEL_QPS:
                samples = sorted({p.info["dns_qname"] for p in long_q or plist})[:5]
                alerts.append(
                    DetectionAlert.build(
                        category=self.name,
                        ts=plist[0].ts,
                        severity="high",
                        title=f"Suspicious DNS activity from {src}",
                        description=(
                            f"{len(long_q)} oversized DNS queries (>={DNS_TUNNEL_QNAME_LEN} chars); "
                            f"rate ~{qps:.1f} q/s."
                        ),
                        src_ip=src,
                        evidence={
                            "long_query_count": len(long_q),
                            "total_queries": len(plist),
                            "qps": round(qps, 2),
                            "samples": samples,
                        },
                    )
                )
        return alerts

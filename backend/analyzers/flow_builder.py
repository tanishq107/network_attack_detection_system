"""Aggregate parsed packets into 5-tuple flows."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from backend.parsers import ParsedPacket


@dataclass
class FlowRecord:
    src_ip: str
    dst_ip: str
    src_port: int | None
    dst_port: int | None
    protocol: str
    start_ts: float
    end_ts: float
    packets: int = 0
    bytes: int = 0
    flags: list[str] = field(default_factory=list)


def _key(p: ParsedPacket) -> tuple:
    # Bi-directional key (sorted endpoints).
    a = (p.src_ip or "", p.src_port or 0)
    b = (p.dst_ip or "", p.dst_port or 0)
    lo, hi = sorted([a, b])
    return (lo[0], lo[1], hi[0], hi[1], p.protocol)


def build_flows(packets: Iterable[ParsedPacket]) -> list[FlowRecord]:
    flows: dict[tuple, FlowRecord] = {}
    for p in packets:
        if not p.src_ip or not p.dst_ip:
            continue
        k = _key(p)
        f = flows.get(k)
        if f is None:
            f = FlowRecord(
                src_ip=p.src_ip,
                dst_ip=p.dst_ip,
                src_port=p.src_port,
                dst_port=p.dst_port,
                protocol=p.protocol,
                start_ts=p.ts,
                end_ts=p.ts,
            )
            flows[k] = f
        f.end_ts = max(f.end_ts, p.ts)
        f.start_ts = min(f.start_ts, p.ts)
        f.packets += 1
        f.bytes += p.length
        if p.tcp_flags:
            f.flags.append(p.tcp_flags)
    return list(flows.values())

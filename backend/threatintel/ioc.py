"""Threat intelligence stub.

Looks up IPs/domains against a local newline-delimited IOC file
(`backend/threatintel/iocs.txt`). Each line: `ip_or_cidr,category`.
Lines starting with `#` are ignored.

Replace with real feeds (MISP, AbuseIPDB, OTX, etc.) as needed.
"""
from __future__ import annotations

import ipaddress
from functools import lru_cache
from pathlib import Path

_IOC_FILE = Path(__file__).resolve().parent / "iocs.txt"


@lru_cache(maxsize=1)
def _load() -> list[tuple[ipaddress._BaseNetwork, str]]:
    out: list[tuple[ipaddress._BaseNetwork, str]] = []
    if not _IOC_FILE.exists():
        return out
    for raw in _IOC_FILE.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in line.split(",", 1)]
        ip_str = parts[0]
        category = parts[1] if len(parts) > 1 else "ioc"
        try:
            if "/" not in ip_str:
                ip_str = ip_str + ("/32" if ":" not in ip_str else "/128")
            net = ipaddress.ip_network(ip_str, strict=False)
            out.append((net, category))
        except ValueError:
            continue
    return out


def lookup_ip(ip: str | None) -> dict | None:
    if not ip:
        return None
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for net, category in _load():
        if addr in net:
            return {"ip": ip, "category": category}
    return None

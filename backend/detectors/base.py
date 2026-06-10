"""Common base class & types for detectors."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Protocol

from backend.parsers import ParsedPacket

from .mitre_map import MITRE_MAP


@dataclass
class DetectionAlert:
    ts: float
    severity: str
    category: str
    title: str
    description: str
    src_ip: str | None = None
    dst_ip: str | None = None
    evidence: dict = field(default_factory=dict)
    mitre_tactic: str | None = None
    mitre_technique: str | None = None
    mitre_id: str | None = None

    @classmethod
    def build(cls, category: str, **kwargs) -> "DetectionAlert":
        mitre = MITRE_MAP.get(category, {})
        kwargs.setdefault("mitre_tactic", mitre.get("tactic"))
        kwargs.setdefault("mitre_technique", mitre.get("technique"))
        kwargs.setdefault("mitre_id", mitre.get("id"))
        return cls(category=category, **kwargs)


class Detector(Protocol):
    name: str

    def detect(self, packets: list[ParsedPacket]) -> Iterable[DetectionAlert]:
        ...

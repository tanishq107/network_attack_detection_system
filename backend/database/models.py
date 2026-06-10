"""ORM models for packets, flows, alerts, uploads."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    JSON,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .session import Base


class Upload(Base):
    __tablename__ = "uploads"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    filename: Mapped[str] = mapped_column(String(255))
    path: Mapped[str] = mapped_column(String(1024))
    size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    uploaded_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    packet_count: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String(32), default="pending")

    packets: Mapped[list["Packet"]] = relationship(back_populates="upload", cascade="all,delete")
    flows: Mapped[list["Flow"]] = relationship(back_populates="upload", cascade="all,delete")
    alerts: Mapped[list["Alert"]] = relationship(back_populates="upload", cascade="all,delete")


class Packet(Base):
    __tablename__ = "packets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    upload_id: Mapped[int] = mapped_column(ForeignKey("uploads.id", ondelete="CASCADE"), index=True)
    ts: Mapped[float] = mapped_column(Float, index=True)
    src_ip: Mapped[str | None] = mapped_column(String(64), index=True)
    dst_ip: Mapped[str | None] = mapped_column(String(64), index=True)
    src_port: Mapped[int | None] = mapped_column(Integer)
    dst_port: Mapped[int | None] = mapped_column(Integer)
    protocol: Mapped[str | None] = mapped_column(String(16), index=True)
    length: Mapped[int] = mapped_column(Integer, default=0)
    tcp_flags: Mapped[str | None] = mapped_column(String(16))
    info: Mapped[dict | None] = mapped_column(JSON)

    upload: Mapped[Upload] = relationship(back_populates="packets")


class Flow(Base):
    __tablename__ = "flows"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    upload_id: Mapped[int] = mapped_column(ForeignKey("uploads.id", ondelete="CASCADE"), index=True)
    src_ip: Mapped[str] = mapped_column(String(64), index=True)
    dst_ip: Mapped[str] = mapped_column(String(64), index=True)
    src_port: Mapped[int | None] = mapped_column(Integer)
    dst_port: Mapped[int | None] = mapped_column(Integer)
    protocol: Mapped[str] = mapped_column(String(16))
    start_ts: Mapped[float] = mapped_column(Float)
    end_ts: Mapped[float] = mapped_column(Float)
    packets: Mapped[int] = mapped_column(Integer, default=0)
    bytes: Mapped[int] = mapped_column(Integer, default=0)

    upload: Mapped[Upload] = relationship(back_populates="flows")


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    upload_id: Mapped[int] = mapped_column(ForeignKey("uploads.id", ondelete="CASCADE"), index=True)
    ts: Mapped[float] = mapped_column(Float, index=True)
    severity: Mapped[str] = mapped_column(String(16), index=True)  # low/medium/high/critical
    category: Mapped[str] = mapped_column(String(64), index=True)  # detector name
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text)
    src_ip: Mapped[str | None] = mapped_column(String(64), index=True)
    dst_ip: Mapped[str | None] = mapped_column(String(64), index=True)
    mitre_tactic: Mapped[str | None] = mapped_column(String(64))
    mitre_technique: Mapped[str | None] = mapped_column(String(64))
    mitre_id: Mapped[str | None] = mapped_column(String(32))
    evidence: Mapped[dict | None] = mapped_column(JSON)

    upload: Mapped[Upload] = relationship(back_populates="alerts")


class SuricataRule(Base):
    __tablename__ = "suricata_rules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    sid: Mapped[int] = mapped_column(Integer, unique=True, index=True)
    name: Mapped[str] = mapped_column(String(255))
    category: Mapped[str] = mapped_column(String(64), index=True)
    rule_text: Mapped[str] = mapped_column(Text)
    source: Mapped[str] = mapped_column(String(32), default="custom", index=True)  # bundled|custom|imported
    enabled: Mapped[bool] = mapped_column(default=True)
    mitre_id: Mapped[str | None] = mapped_column(String(32))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

"""End-to-end PCAP processing pipeline."""
from __future__ import annotations

import logging
from dataclasses import asdict

from sqlalchemy.orm import Session

from backend.analyzers import build_flows
from backend.database import models
from backend.detectors import run_all
from backend.parsers import parse_pcap

log = logging.getLogger(__name__)

_PACKET_BATCH = 500


def process_upload(db: Session, upload: models.Upload) -> dict:
    """Parse the PCAP referenced by *upload*, persist artifacts, run detectors."""
    upload.status = "processing"
    db.commit()

    parsed_packets = []
    try:
        batch: list[models.Packet] = []
        for parsed in parse_pcap(upload.path):
            parsed_packets.append(parsed)
            batch.append(
                models.Packet(
                    upload_id=upload.id,
                    ts=parsed.ts,
                    src_ip=parsed.src_ip,
                    dst_ip=parsed.dst_ip,
                    src_port=parsed.src_port,
                    dst_port=parsed.dst_port,
                    protocol=parsed.protocol,
                    length=parsed.length,
                    tcp_flags=parsed.tcp_flags,
                    info=parsed.info or None,
                )
            )
            if len(batch) >= _PACKET_BATCH:
                db.add_all(batch)
                db.commit()
                batch.clear()
        if batch:
            db.add_all(batch)
            db.commit()

        # Flows
        flows = build_flows(parsed_packets)
        db.add_all(
            models.Flow(
                upload_id=upload.id,
                src_ip=f.src_ip,
                dst_ip=f.dst_ip,
                src_port=f.src_port,
                dst_port=f.dst_port,
                protocol=f.protocol,
                start_ts=f.start_ts,
                end_ts=f.end_ts,
                packets=f.packets,
                bytes=f.bytes,
            )
            for f in flows
        )

        # Detectors
        alerts = run_all(parsed_packets)
        db.add_all(
            models.Alert(
                upload_id=upload.id,
                ts=a.ts,
                severity=a.severity,
                category=a.category,
                title=a.title,
                description=a.description,
                src_ip=a.src_ip,
                dst_ip=a.dst_ip,
                mitre_tactic=a.mitre_tactic,
                mitre_technique=a.mitre_technique,
                mitre_id=a.mitre_id,
                evidence=a.evidence,
            )
            for a in alerts
        )

        upload.packet_count = len(parsed_packets)
        upload.status = "done"
        db.commit()

        return {
            "upload_id": upload.id,
            "packets": len(parsed_packets),
            "flows": len(flows),
            "alerts": len(alerts),
        }
    except Exception as exc:
        db.rollback()
        upload.status = f"error: {exc.__class__.__name__}"
        db.commit()
        log.exception("Pipeline failed for upload %s", upload.id)
        raise

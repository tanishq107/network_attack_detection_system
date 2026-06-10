"""Report generation: JSON, HTML, optional PDF."""
from __future__ import annotations

import json
from collections import Counter
from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape
from sqlalchemy.orm import Session

from backend.database import models

_TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"
_env = Environment(
    loader=FileSystemLoader(str(_TEMPLATE_DIR)),
    autoescape=select_autoescape(["html", "xml"]),
)


REMEDIATION = {
    "port_scan": "Block scanning source at the perimeter; enable rate limiting on edge firewalls.",
    "syn_flood": "Enable SYN cookies, deploy upstream DDoS scrubbing, and rate-limit incoming SYNs.",
    "dns_tunneling": "Inspect DNS via a recursive resolver with anomaly detection; block the offending domain.",
    "brute_force": "Enforce MFA, account lockout, fail2ban-style throttling, and source-IP allowlists.",
    "beaconing": "Investigate originating host for malware; block destination at firewall/proxy.",
    "arp_spoofing": "Enable Dynamic ARP Inspection (DAI) and DHCP snooping on the LAN.",
    "malware_traffic": "Isolate host; perform full forensic triage; rotate credentials; rebuild if compromised.",
}


def _summarize(upload: models.Upload) -> dict:
    alerts = upload.alerts
    sev_counts = Counter(a.severity for a in alerts)
    cat_counts = Counter(a.category for a in alerts)
    iocs = []
    for a in alerts:
        if a.src_ip:
            iocs.append(a.src_ip)
        if a.dst_ip:
            iocs.append(a.dst_ip)
    ioc_counts = Counter(iocs).most_common(25)
    mitre = sorted({(a.mitre_id, a.mitre_tactic, a.mitre_technique) for a in alerts if a.mitre_id})
    return {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "upload": {
            "id": upload.id,
            "filename": upload.filename,
            "uploaded_at": upload.uploaded_at.isoformat() + "Z",
            "packet_count": upload.packet_count,
            "size_bytes": upload.size_bytes,
        },
        "executive_summary": {
            "total_alerts": len(alerts),
            "by_severity": dict(sev_counts),
            "by_category": dict(cat_counts),
        },
        "iocs": [{"indicator": ip, "hits": n} for ip, n in ioc_counts],
        "mitre": [
            {"id": mid, "tactic": tac, "technique": tech}
            for (mid, tac, tech) in mitre
        ],
        "alerts": [
            {
                "id": a.id,
                "ts": a.ts,
                "severity": a.severity,
                "category": a.category,
                "title": a.title,
                "description": a.description,
                "src_ip": a.src_ip,
                "dst_ip": a.dst_ip,
                "mitre_id": a.mitre_id,
                "mitre_tactic": a.mitre_tactic,
                "mitre_technique": a.mitre_technique,
                "evidence": a.evidence,
            }
            for a in alerts
        ],
        "remediation": [
            {"category": cat, "recommendation": REMEDIATION.get(cat, "Investigate further.")}
            for cat in sorted(cat_counts)
        ],
    }


def build_json(db: Session, upload_id: int) -> str:
    upload = db.get(models.Upload, upload_id)
    if not upload:
        raise ValueError(f"upload {upload_id} not found")
    return json.dumps(_summarize(upload), indent=2, default=str)


def build_html(db: Session, upload_id: int) -> str:
    upload = db.get(models.Upload, upload_id)
    if not upload:
        raise ValueError(f"upload {upload_id} not found")
    data = _summarize(upload)
    template = _env.get_template("report.html.j2")
    return template.render(**data)


def build_pdf(db: Session, upload_id: int, output_path: str) -> str:
    html = build_html(db, upload_id)
    try:
        from weasyprint import HTML  # type: ignore
    except Exception as exc:  # pragma: no cover
        raise RuntimeError(
            "WeasyPrint not available. Install system deps (cairo, pango) or use HTML format."
        ) from exc
    HTML(string=html).write_pdf(output_path)
    return output_path

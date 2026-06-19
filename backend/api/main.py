"""FastAPI application entrypoint."""
from __future__ import annotations

import shutil
import uuid
from collections import Counter
from datetime import datetime
from pathlib import Path

from fastapi import Depends, FastAPI, File, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.config import REPORT_DIR, UPLOAD_DIR
from backend.database import get_db, init_db, models
from backend.live import LiveSniffer, list_interfaces
from backend.reports import build_html, build_json, build_pdf
from backend.suricata import DEFAULT_RULES, parse_rule, run_rules, suricata_binary

from .pipeline import process_upload

app = FastAPI(title="Network Attack Detection Engine", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def _startup() -> None:
    init_db()
    _seed_default_rules()


def _seed_default_rules() -> None:
    """Insert/refresh bundled Suricata rules.

    Inserts new rules and updates the text/name/category of any existing
    bundled rule whose definition has changed. Per-row `enabled` state is
    preserved across upgrades, except on first install where the rule's
    `enabled_by_default` flag (if present) wins.
    """
    from backend.database.session import SessionLocal

    with SessionLocal() as db:
        existing = {
            r.sid: r for r in db.execute(select(models.SuricataRule)).scalars().all()
        }
        for rule in DEFAULT_RULES:
            sid = rule["sid"]
            row = existing.get(sid)
            if row is None:
                db.add(
                    models.SuricataRule(
                        sid=sid,
                        name=rule["name"],
                        category=rule["category"],
                        rule_text=rule["rule_text"],
                        source="bundled",
                        enabled=rule.get("enabled_by_default", True),
                        mitre_id=rule.get("mitre_id"),
                    )
                )
            elif row.source == "bundled" and row.rule_text != rule["rule_text"]:
                # Rule text changed in a release — refresh it (preserve enabled state).
                row.rule_text = rule["rule_text"]
                row.name = rule["name"]
                row.category = rule["category"]
                row.mitre_id = rule.get("mitre_id")
                # If the rule ships disabled-by-default and we're refreshing
                # from an older noisy version, also flip enabled off so the
                # upgrade actually silences the false positives.
                if rule.get("enabled_by_default") is False:
                    row.enabled = False
        db.commit()


@app.get("/api/health")
def health() -> dict:
    return {"status": "ok", "time": datetime.utcnow().isoformat() + "Z"}


@app.post("/api/upload")
async def upload_pcap(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
) -> dict:
    if not file.filename:
        raise HTTPException(400, "filename required")
    suffix = Path(file.filename).suffix or ".pcap"
    stored = UPLOAD_DIR / f"{uuid.uuid4().hex}{suffix}"
    with stored.open("wb") as out:
        shutil.copyfileobj(file.file, out)
    size = stored.stat().st_size

    upload = models.Upload(
        filename=file.filename,
        path=str(stored),
        size_bytes=size,
        status="pending",
    )
    db.add(upload)
    db.commit()
    db.refresh(upload)

    try:
        result = process_upload(db, upload)
    except Exception as exc:
        raise HTTPException(500, f"processing failed: {exc}") from exc

    return {"upload": _serialize_upload(upload), **result}


@app.get("/api/uploads")
def list_uploads(db: Session = Depends(get_db)) -> list[dict]:
    rows = db.execute(select(models.Upload).order_by(models.Upload.id.desc())).scalars().all()
    return [_serialize_upload(u) for u in rows]


@app.get("/api/uploads/{upload_id}/download")
def download_upload(upload_id: int, db: Session = Depends(get_db)):
    upload = db.get(models.Upload, upload_id)
    if not upload:
        raise HTTPException(404, "upload not found")

    # If this is the still-running live session the pcap may not be flushed.
    sniffer = LiveSniffer.get()
    if sniffer.is_running() and sniffer.upload_id == upload.id:
        raise HTTPException(
            409,
            "live session still running; stop the sniffer to flush the capture before downloading",
        )

    p = Path(upload.path) if upload.path else None
    if p is None or not p.is_file():
        raise HTTPException(404, "capture file not on disk")

    # Use the human-friendly filename for the download. Keep the suffix the
    # stored file actually has (it'll usually be .pcap, but we don't force it).
    download_name = upload.filename or p.name
    if not Path(download_name).suffix:
        download_name += p.suffix or ".pcap"
    # Replace path separators / colons that would break Content-Disposition.
    download_name = download_name.replace("/", "_").replace(":", "_")
    return FileResponse(
        path=str(p),
        media_type="application/vnd.tcpdump.pcap",
        filename=download_name,
    )


@app.delete("/api/uploads/{upload_id}")
def delete_upload(upload_id: int, db: Session = Depends(get_db)) -> dict:
    upload = db.get(models.Upload, upload_id)
    if not upload:
        raise HTTPException(404, "upload not found")

    # Refuse to delete the upload row currently owned by a running live
    # sniffer session — stop the sniffer first.
    sniffer = LiveSniffer.get()
    if sniffer.is_running() and sniffer.upload_id == upload.id:
        raise HTTPException(
            409,
            "upload is the active live sniffer session; stop the sniffer first",
        )

    # Try to remove the on-disk pcap. Skip the legacy `live://...` pseudo-path
    # used by older live sessions (those have no on-disk file).
    file_removed = False
    if upload.path and not str(upload.path).startswith("live://"):
        try:
            p = Path(upload.path)
            if p.is_file():
                p.unlink()
                file_removed = True
        except OSError:
            # leave the DB delete to proceed; surface only via response
            pass

    # Best-effort report cleanup.
    report_pdf = REPORT_DIR / f"upload-{upload_id}.pdf"
    if report_pdf.exists():
        try:
            report_pdf.unlink()
        except OSError:
            pass

    db.delete(upload)  # cascades to packets / flows / alerts
    db.commit()
    return {"deleted": upload_id, "file_removed": file_removed}


@app.get("/api/alerts")
def list_alerts(
    upload_id: int | None = Query(None),
    severity: str | None = Query(None),
    category: str | None = Query(None),
    limit: int = Query(500, ge=1, le=10000),
    db: Session = Depends(get_db),
) -> list[dict]:
    stmt = select(models.Alert).order_by(models.Alert.ts.desc())
    if upload_id is not None:
        stmt = stmt.where(models.Alert.upload_id == upload_id)
    if severity:
        stmt = stmt.where(models.Alert.severity == severity)
    if category:
        stmt = stmt.where(models.Alert.category == category)
    stmt = stmt.limit(limit)
    return [_serialize_alert(a) for a in db.execute(stmt).scalars().all()]


@app.get("/api/summary")
def summary(
    upload_id: int | None = Query(None),
    db: Session = Depends(get_db),
) -> dict:
    base = select(models.Alert)
    if upload_id is not None:
        base = base.where(models.Alert.upload_id == upload_id)
    alerts = db.execute(base).scalars().all()
    sev = Counter(a.severity for a in alerts)
    cat = Counter(a.category for a in alerts)
    mitre = Counter(a.mitre_id for a in alerts if a.mitre_id)

    pkt_stmt = select(func.count(models.Packet.id))
    flow_stmt = select(func.count(models.Flow.id))
    if upload_id is not None:
        pkt_stmt = pkt_stmt.where(models.Packet.upload_id == upload_id)
        flow_stmt = flow_stmt.where(models.Flow.upload_id == upload_id)
    packet_count = db.execute(pkt_stmt).scalar_one()
    flow_count = db.execute(flow_stmt).scalar_one()

    # Live captures stream packets to a PCAP file but do not insert per-packet
    # rows into the `packets` table, so the count above is 0 for them. Fall
    # back to the running tally stored on the Upload row in that case.
    if upload_id is not None and packet_count == 0:
        upload_row = db.get(models.Upload, upload_id)
        if upload_row and upload_row.packet_count:
            packet_count = upload_row.packet_count

    return {
        "upload_id": upload_id,
        "totals": {
            "packets": packet_count,
            "flows": flow_count,
            "alerts": len(alerts),
        },
        "by_severity": dict(sev),
        "by_category": dict(cat),
        "by_mitre": dict(mitre),
    }


@app.get("/api/timeline")
def timeline(
    upload_id: int | None = Query(None),
    buckets: int = Query(50, ge=1, le=500),
    db: Session = Depends(get_db),
) -> dict:
    stmt = select(models.Alert.ts, models.Alert.severity)
    if upload_id is not None:
        stmt = stmt.where(models.Alert.upload_id == upload_id)
    rows = db.execute(stmt).all()
    if not rows:
        return {"buckets": [], "counts": []}
    ts_list = [r[0] for r in rows]
    lo, hi = min(ts_list), max(ts_list)
    if hi == lo:
        hi = lo + 1.0
    width = (hi - lo) / buckets
    out = [{"ts": lo + i * width, "count": 0} for i in range(buckets)]
    for ts, _sev in rows:
        idx = min(int((ts - lo) / width), buckets - 1)
        out[idx]["count"] += 1
    return {"start_ts": lo, "end_ts": hi, "bucket_sec": width, "buckets": out}


@app.get("/api/report/{upload_id}")
def get_report(
    upload_id: int,
    format: str = Query("json", pattern="^(json|html|pdf)$"),
    db: Session = Depends(get_db),
):
    upload = db.get(models.Upload, upload_id)
    if not upload:
        raise HTTPException(404, "upload not found")

    if format == "json":
        return JSONResponse(content=__import__("json").loads(build_json(db, upload_id)))
    if format == "html":
        return HTMLResponse(content=build_html(db, upload_id))
    # pdf
    out_path = REPORT_DIR / f"upload-{upload_id}.pdf"
    try:
        build_pdf(db, upload_id, str(out_path))
    except RuntimeError as exc:
        raise HTTPException(503, str(exc)) from exc
    return Response(
        content=out_path.read_bytes(),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="report-{upload_id}.pdf"'},
    )


# ---------------------------------------------------------------------------
# Suricata rules
# ---------------------------------------------------------------------------


class RuleCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    category: str = Field("custom", max_length=64)
    rule_text: str = Field(..., min_length=10)
    sid: int | None = None
    enabled: bool = True


class RulePatch(BaseModel):
    enabled: bool | None = None
    name: str | None = None
    category: str | None = None
    rule_text: str | None = None


class RuleImport(BaseModel):
    text: str | None = None
    url: str | None = None
    source_label: str = "imported"


@app.get("/api/rules")
def list_rules(
    enabled: bool | None = Query(None),
    source: str | None = Query(None),
    db: Session = Depends(get_db),
) -> dict:
    stmt = select(models.SuricataRule).order_by(models.SuricataRule.sid)
    if enabled is not None:
        stmt = stmt.where(models.SuricataRule.enabled == enabled)
    if source:
        stmt = stmt.where(models.SuricataRule.source == source)
    rows = db.execute(stmt).scalars().all()
    return {
        "engine": "suricata" if suricata_binary() else "nade-emulator",
        "binary": suricata_binary(),
        "count": len(rows),
        "rules": [_serialize_rule(r) for r in rows],
    }


@app.post("/api/rules", status_code=201)
def create_rule(payload: RuleCreate, db: Session = Depends(get_db)) -> dict:
    parsed = parse_rule(payload.rule_text)
    sid = payload.sid or (parsed.sid if parsed and parsed.sid else _next_sid(db))
    if db.execute(select(models.SuricataRule).where(models.SuricataRule.sid == sid)).first():
        raise HTTPException(409, f"rule with sid {sid} already exists")
    rule = models.SuricataRule(
        sid=sid,
        name=payload.name,
        category=payload.category,
        rule_text=payload.rule_text,
        source="custom",
        enabled=payload.enabled,
        mitre_id=(parsed.mitre_id if parsed else None),
    )
    db.add(rule)
    db.commit()
    db.refresh(rule)
    return _serialize_rule(rule)


@app.patch("/api/rules/{rule_id}")
def update_rule(rule_id: int, payload: RulePatch, db: Session = Depends(get_db)) -> dict:
    rule = db.get(models.SuricataRule, rule_id)
    if not rule:
        raise HTTPException(404, "rule not found")
    if payload.enabled is not None:
        rule.enabled = payload.enabled
    if payload.name is not None:
        rule.name = payload.name
    if payload.category is not None:
        rule.category = payload.category
    if payload.rule_text is not None:
        if rule.source == "bundled":
            raise HTTPException(400, "cannot edit text of bundled rule; clone as custom instead")
        rule.rule_text = payload.rule_text
        parsed = parse_rule(payload.rule_text)
        if parsed and parsed.mitre_id:
            rule.mitre_id = parsed.mitre_id
    db.commit()
    db.refresh(rule)
    return _serialize_rule(rule)


@app.delete("/api/rules/{rule_id}", status_code=204)
def delete_rule(rule_id: int, db: Session = Depends(get_db)):
    rule = db.get(models.SuricataRule, rule_id)
    if not rule:
        raise HTTPException(404, "rule not found")
    if rule.source == "bundled":
        raise HTTPException(400, "cannot delete bundled rule; disable it instead")
    db.delete(rule)
    db.commit()
    return Response(status_code=204)


@app.post("/api/rules/import")
def import_rules(payload: RuleImport, db: Session = Depends(get_db)) -> dict:
    text = payload.text or ""
    if payload.url:
        import requests

        try:
            r = requests.get(payload.url, timeout=20)
            r.raise_for_status()
            text = r.text
        except Exception as exc:
            raise HTTPException(502, f"download failed: {exc}") from exc

    if not text.strip():
        raise HTTPException(400, "no rule text provided")

    added = 0
    skipped = 0
    errors: list[str] = []
    next_sid = _next_sid(db)
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parsed = parse_rule(line)
        if not parsed:
            skipped += 1
            continue
        sid = parsed.sid or next_sid
        if not parsed.sid:
            next_sid += 1
        if db.execute(select(models.SuricataRule).where(models.SuricataRule.sid == sid)).first():
            skipped += 1
            continue
        try:
            db.add(
                models.SuricataRule(
                    sid=sid,
                    name=parsed.msg or f"Imported rule {sid}",
                    category=parsed.classtype or "imported",
                    rule_text=line,
                    source=payload.source_label,
                    enabled=True,
                    mitre_id=parsed.mitre_id,
                )
            )
            added += 1
        except Exception as exc:
            errors.append(str(exc))
    db.commit()
    return {"added": added, "skipped": skipped, "errors": errors[:10]}


@app.post("/api/rules/run/{upload_id}")
def run_rules_against_upload(upload_id: int, db: Session = Depends(get_db)) -> dict:
    upload = db.get(models.Upload, upload_id)
    if not upload:
        raise HTTPException(404, "upload not found")

    rules = db.execute(
        select(models.SuricataRule).where(models.SuricataRule.enabled == True)  # noqa: E712
    ).scalars().all()

    # Clear prior Suricata alerts for this upload so re-runs replace results
    # instead of accumulating duplicates. Python-detector alerts are kept.
    cleared = (
        db.query(models.Alert)
        .filter(
            models.Alert.upload_id == upload.id,
            models.Alert.category.like("suricata:%"),
        )
        .delete(synchronize_session=False)
    )

    alerts, meta = run_rules(upload.path, rules)

    persisted = 0
    for a in alerts:
        db.add(
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
        )
        persisted += 1
    db.commit()
    return {"upload_id": upload.id, "cleared": cleared, "persisted": persisted, **meta}


# ---------------------------------------------------------------------------
# Live sniffer
# ---------------------------------------------------------------------------


class LiveStartRequest(BaseModel):
    interface: str = Field(..., min_length=1, max_length=64)
    bpf_filter: str | None = Field(None, max_length=512)
    with_suricata: bool = False


@app.get("/api/live/interfaces")
def live_interfaces() -> dict:
    return {"interfaces": list_interfaces()}


@app.get("/api/live/status")
def live_status() -> dict:
    return LiveSniffer.get().status()


@app.post("/api/live/start")
def live_start(req: LiveStartRequest) -> dict:
    sniffer = LiveSniffer.get()
    try:
        return sniffer.start(req.interface, req.bpf_filter, with_suricata=req.with_suricata)
    except RuntimeError as exc:
        raise HTTPException(400, str(exc)) from exc


@app.post("/api/live/stop")
def live_stop() -> dict:
    sniffer = LiveSniffer.get()
    if not sniffer.is_running():
        raise HTTPException(400, "live sniffer is not running")
    return sniffer.stop()


@app.on_event("shutdown")
def _shutdown_live() -> None:
    sniffer = LiveSniffer.get()
    if sniffer.is_running():
        try:
            sniffer.stop()
        except Exception:
            pass


def _next_sid(db: Session) -> int:
    cur = db.execute(select(func.max(models.SuricataRule.sid))).scalar()
    return max(int(cur or 0), 1_000_000) + 1


def _serialize_rule(r: models.SuricataRule) -> dict:
    return {
        "id": r.id,
        "sid": r.sid,
        "name": r.name,
        "category": r.category,
        "rule_text": r.rule_text,
        "source": r.source,
        "enabled": r.enabled,
        "mitre_id": r.mitre_id,
        "created_at": r.created_at.isoformat() + "Z",
    }


def _serialize_upload(u: models.Upload) -> dict:
    return {
        "id": u.id,
        "filename": u.filename,
        "size_bytes": u.size_bytes,
        "uploaded_at": u.uploaded_at.isoformat() + "Z",
        "packet_count": u.packet_count,
        "status": u.status,
        # Older `live://...` sessions have no on-disk file; expose a hint
        # so the UI can hide the download link for them.
        "has_capture": bool(u.path) and not str(u.path).startswith("live://"),
    }


def _serialize_alert(a: models.Alert) -> dict:
    return {
        "id": a.id,
        "upload_id": a.upload_id,
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

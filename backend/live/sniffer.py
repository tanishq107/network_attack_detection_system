"""Live network sniffer.

Runs `scapy.AsyncSniffer` in a background thread, parses each frame with the
existing pcap parser, keeps a sliding window in memory, and every
``scan_interval`` seconds runs all NADE Python detectors over that window.

Alerts are deduplicated by ``(category, src_ip, dst_ip)`` for ``dedup_ttl``
seconds so noisy sources don't generate one alert per scan tick. Persisted
alerts are attached to a synthetic ``Upload`` row whose ``filename`` starts
with ``LIVE:`` so the existing dashboard shows them under that "upload".

Capturing on most interfaces requires elevated privileges on macOS / Linux.
If sniff() fails (no permission, missing libpcap, bad interface), the error
is captured and surfaced via the status endpoint.
"""
from __future__ import annotations

import logging
import threading
import time
from collections import deque
from datetime import datetime
from pathlib import Path
from typing import Optional

from backend.config import UPLOAD_DIR
from backend.database import models
from backend.database.session import SessionLocal
from backend.detectors import run_all
from backend.parsers.pcap_parser import _parse_packet
from backend.suricata import suricata_binary

from .suricata_live import SuricataLive

log = logging.getLogger(__name__)


def list_interfaces() -> list[str]:
    """Best-effort list of capture interfaces."""
    try:
        from scapy.all import get_if_list  # type: ignore

        return sorted(get_if_list())
    except Exception as exc:  # pragma: no cover - platform dependent
        log.warning("get_if_list failed: %s", exc)
        return []


class LiveSniffer:
    """Singleton in-process sniffer.

    The detectors are stateless across calls, so a single global instance is
    enough — and it keeps semantics simple ("there is at most one live
    session at a time").
    """

    _instance: "LiveSniffer | None" = None

    def __init__(self) -> None:
        self._sniffer = None
        self._scanner_thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._lock = threading.RLock()

        self.interface: str | None = None
        self.bpf_filter: str | None = None
        self.upload_id: int | None = None
        self.started_at: float | None = None
        self.error: str | None = None

        self._suricata: SuricataLive | None = None
        self.with_suricata: bool = False

        # PCAP recording (raw scapy packets → disk so the user can download
        # the traffic later). Created lazily in _on_packet so we capture the
        # link-layer of whatever Scapy hands us first.
        self._pcap_writer = None
        self._pcap_lock = threading.Lock()
        self._pcap_path: Path | None = None
        self._pcap_bytes: int = 0

        self.window_sec = 60        # detector window
        self.scan_interval = 5      # seconds between detector runs
        self.dedup_ttl = 300        # how long to suppress repeats
        self.buffer_max = 50_000    # hard cap on in-memory packets

        self._buffer: deque = deque(maxlen=self.buffer_max)
        self._dedup: dict[tuple, float] = {}

        self.packet_count = 0
        self.alert_count = 0
        self.last_scan_at: float | None = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    @classmethod
    def get(cls) -> "LiveSniffer":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def is_running(self) -> bool:
        return bool(self._sniffer and getattr(self._sniffer, "running", False))

    def start(
        self,
        interface: str,
        bpf_filter: str | None = None,
        with_suricata: bool = False,
    ) -> dict:
        with self._lock:
            if self.is_running():
                raise RuntimeError("live sniffer already running")
            try:
                from scapy.all import AsyncSniffer  # type: ignore
            except Exception as exc:  # pragma: no cover
                raise RuntimeError(f"scapy not available: {exc}") from exc

            # reset state
            self._buffer.clear()
            self._dedup.clear()
            self._stop_event.clear()
            self.packet_count = 0
            self.alert_count = 0
            self.last_scan_at = None
            self.error = None
            self.interface = interface
            self.bpf_filter = bpf_filter or None
            self.with_suricata = bool(with_suricata)
            self._suricata = None
            self.started_at = time.time()
            self._pcap_writer = None
            self._pcap_path = None
            self._pcap_bytes = 0

            with SessionLocal() as db:
                # safe-ish filename derived from interface + timestamp
                ts_label = datetime.utcnow().strftime('%Y%m%d-%H%M%S')
                safe_iface = "".join(
                    c if c.isalnum() or c in "-_." else "_" for c in interface
                )
                pcap_filename = f"live-{safe_iface}-{ts_label}.pcap"
                self._pcap_path = Path(UPLOAD_DIR) / pcap_filename
                upload = models.Upload(
                    filename=f"LIVE:{interface}@{ts_label}",
                    path=str(self._pcap_path),
                    size_bytes=0,
                    status="live",
                )
                db.add(upload)
                db.commit()
                db.refresh(upload)
                self.upload_id = upload.id

            try:
                self._sniffer = AsyncSniffer(
                    iface=interface,
                    prn=self._on_packet,
                    filter=self.bpf_filter,
                    store=False,
                )
                self._sniffer.start()
            except Exception as exc:
                self.error = f"sniffer start failed: {exc}"
                self._mark_upload_status("error")
                raise RuntimeError(self.error) from exc

            self._scanner_thread = threading.Thread(
                target=self._scanner_loop, daemon=True, name="nade-live-scanner"
            )
            self._scanner_thread.start()

            if self.with_suricata:
                try:
                    self._start_suricata_live()
                except Exception as exc:
                    # Don't tear down the Scapy sniffer if Suricata can't start;
                    # surface the error and continue with Python detectors only.
                    log.warning("live suricata failed to start: %s", exc)
                    self.error = f"suricata: {exc}"

            log.info("Live sniffer started on %s (filter=%r) upload=%s suricata=%s",
                     interface, bpf_filter, self.upload_id, self.with_suricata)
            return self.status()

    def _start_suricata_live(self) -> None:
        if suricata_binary() is None:
            raise RuntimeError("suricata binary not found")
        # Pull enabled rules from DB so the live IDS uses the same set as the
        # offline runner (including user customisations).
        with SessionLocal() as db:
            from sqlalchemy import select  # local import to keep module light

            rows = db.execute(
                select(models.SuricataRule).where(models.SuricataRule.enabled == True)  # noqa: E712
            ).scalars().all()
            rule_texts = [r.rule_text for r in rows]
        if self.upload_id is None:
            raise RuntimeError("no live upload row to attach alerts to")
        sl = SuricataLive(self.interface or "", rule_texts, self.upload_id)
        sl.start()
        self._suricata = sl

    def stop(self) -> dict:
        with self._lock:
            self._stop_event.set()
            if self._sniffer is not None:
                try:
                    self._sniffer.stop()
                except Exception as exc:  # pragma: no cover
                    log.warning("Sniffer stop raised: %s", exc)
            if self._scanner_thread and self._scanner_thread.is_alive():
                self._scanner_thread.join(timeout=3)

            # final detector pass over whatever is left
            try:
                self._scan_once()
            except Exception as exc:  # pragma: no cover
                log.warning("Final scan failed: %s", exc)

            if self._suricata is not None:
                try:
                    self._suricata.stop()
                except Exception as exc:  # pragma: no cover
                    log.warning("Suricata live stop raised: %s", exc)

            # Flush + close pcap writer
            with self._pcap_lock:
                if self._pcap_writer:
                    try:
                        self._pcap_writer.close()
                    except Exception as exc:  # pragma: no cover
                        log.warning("pcap close failed: %s", exc)
                self._pcap_writer = None

            self._mark_upload_status("done")
            self._sniffer = None
            log.info("Live sniffer stopped (packets=%d alerts=%d)",
                     self.packet_count, self.alert_count)
            return self.status()

    def status(self) -> dict:
        return {
            "running": self.is_running(),
            "interface": self.interface,
            "bpf_filter": self.bpf_filter,
            "upload_id": self.upload_id,
            "started_at": self.started_at,
            "packet_count": self.packet_count,
            "alert_count": self.alert_count,
            "buffered_packets": len(self._buffer),
            "last_scan_at": self.last_scan_at,
            "window_sec": self.window_sec,
            "scan_interval_sec": self.scan_interval,
            "error": self.error,
            "with_suricata": self.with_suricata,
            "suricata": self._suricata.status() if self._suricata is not None else None,
            "pcap_path": str(self._pcap_path) if self._pcap_path else None,
            "pcap_bytes": self._pcap_bytes,
        }

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _on_packet(self, raw_pkt) -> None:
        # Persist to disk so the live capture is downloadable later. Lazy
        # init lets us pin the writer's link layer to whatever Scapy gives us
        # first (Ether vs cooked vs loopback all work because PcapWriter
        # accepts any single linktype).
        try:
            with self._pcap_lock:
                if self._pcap_writer is None and self._pcap_path is not None:
                    from scapy.utils import PcapWriter  # type: ignore

                    try:
                        self._pcap_writer = PcapWriter(
                            str(self._pcap_path), append=False, sync=False,
                        )
                    except Exception as exc:
                        log.warning("PcapWriter init failed: %s", exc)
                        self._pcap_writer = False  # sentinel: don't retry
                if self._pcap_writer:
                    self._pcap_writer.write(raw_pkt)
                    try:
                        self._pcap_bytes += len(raw_pkt)
                    except Exception:
                        pass
        except Exception as exc:  # pragma: no cover
            log.debug("pcap write failed: %s", exc)

        try:
            p = _parse_packet(raw_pkt)
        except Exception as exc:  # pragma: no cover
            log.debug("packet parse failed: %s", exc)
            return
        # Scapy sometimes returns ts=0 — fall back to wall clock so detector
        # windowing makes sense.
        if not p.ts:
            p.ts = time.time()
        self._buffer.append(p)
        self.packet_count += 1

    def _scanner_loop(self) -> None:
        while not self._stop_event.is_set():
            # wait but stay responsive to stop()
            self._stop_event.wait(self.scan_interval)
            if self._stop_event.is_set():
                break
            try:
                self._scan_once()
            except Exception as exc:
                log.exception("scan tick failed: %s", exc)
                self.error = f"scan failed: {exc}"

    def _scan_once(self) -> None:
        cutoff = time.time() - self.window_sec
        # snapshot buffer (deque iteration is cheap; we copy refs only)
        packets = [p for p in list(self._buffer) if p.ts >= cutoff]
        if not packets:
            self.last_scan_at = time.time()
            return

        alerts = run_all(packets)

        now = time.time()
        # purge expired dedup entries
        self._dedup = {k: t for k, t in self._dedup.items() if now - t < self.dedup_ttl}

        fresh = []
        for a in alerts:
            fp = (a.category, a.src_ip, a.dst_ip)
            if fp in self._dedup:
                continue
            self._dedup[fp] = now
            fresh.append(a)

        if fresh and self.upload_id is not None:
            with SessionLocal() as db:
                for a in fresh:
                    db.add(
                        models.Alert(
                            upload_id=self.upload_id,
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
                db.commit()
            self.alert_count += len(fresh)

        self.last_scan_at = time.time()

    def _mark_upload_status(self, status: str) -> None:
        if self.upload_id is None:
            return
        try:
            with SessionLocal() as db:
                u = db.get(models.Upload, self.upload_id)
                if u:
                    u.status = status
                    u.packet_count = self.packet_count
                    # Persist real on-disk size of the captured pcap so the
                    # uploads list shows a useful figure for live sessions.
                    if self._pcap_path is not None and self._pcap_path.exists():
                        try:
                            u.size_bytes = self._pcap_path.stat().st_size
                        except OSError:
                            pass
                    db.commit()
        except Exception as exc:  # pragma: no cover
            log.warning("failed to mark upload status: %s", exc)

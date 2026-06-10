"""Live Suricata IDS runner.

Spawns ``suricata -i <iface>`` as a subprocess pointed at a temporary rules
file (the enabled rules from the DB) and a temporary log dir. A background
thread tails ``eve.json`` and, for every alert event, persists a NADE
``Alert`` row attached to the live ``Upload`` row created by the
``LiveSniffer``.

The subprocess and tailer are completely independent from the Scapy-based
sniffer / Python detectors — they just share the same ``upload_id`` so
alerts from both engines surface on the same dashboard.

Privileges: ``suricata -i`` needs raw-socket access. On macOS / Linux the
backend must be started with ``sudo`` (or the suricata binary must have
``cap_net_raw``). If the spawn fails, the error is captured and surfaced
via :meth:`SuricataLive.status`.
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import signal
import subprocess
import tempfile
import threading
import time
from pathlib import Path

from backend.database import models
from backend.database.session import SessionLocal
from backend.suricata import eve_event_to_alert, suricata_binary

log = logging.getLogger(__name__)


class SuricataLive:
    """One-shot live IDS session.

    Construct, ``start()``, and ``stop()`` exactly once. Build a fresh
    instance for each new live session.
    """

    # how long to wait for suricata to create eve.json before declaring start ok
    EVE_WAIT_SEC = 15
    # time between empty reads when tailing eve.json
    TAIL_IDLE_SLEEP = 0.5

    def __init__(self, interface: str, rule_texts: list[str], upload_id: int) -> None:
        self.interface = interface
        self.rule_texts = [t for t in rule_texts if t and t.strip()]
        self.upload_id = upload_id

        self._tmp: tempfile.TemporaryDirectory | None = None
        self._proc: subprocess.Popen | None = None
        self._tailer: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        self._stderr_path: Path | None = None
        self._stderr_fh = None  # type: ignore[assignment]

        self.binary: str | None = suricata_binary()
        self.alert_count = 0
        self.error: str | None = None
        self.started_at: float | None = None
        self.stderr_tail: str = ""

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        if self.binary is None:
            raise RuntimeError(
                "suricata binary not found on PATH (set NADE_SURICATA_BIN or install suricata)"
            )
        if not self.rule_texts:
            raise RuntimeError("no enabled Suricata rules to run live")

        self._tmp = tempfile.TemporaryDirectory(prefix="nade-suri-live-")
        tmp = Path(self._tmp.name)
        rules_file = tmp / "nade.rules"
        log_dir = tmp / "log"
        log_dir.mkdir()
        rules_file.write_text("\n".join(self.rule_texts) + "\n")

        # Redirect stderr to a file so we can tail it from status() without
        # racing the subprocess's pipe reader. Suricata writes its banner +
        # any errors here (e.g. "unable to set caps: Operation not permitted"
        # on macOS without root).
        self._stderr_path = tmp / "stderr.log"
        self._stderr_fh = open(self._stderr_path, "wb")

        cmd = [
            self.binary,
            "-i", self.interface,
            "-l", str(log_dir),
            "-S", str(rules_file),
        ]
        log.info("Starting live Suricata: %s", " ".join(cmd))
        try:
            self._proc = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=self._stderr_fh,
                # new process group so we can kill the whole tree cleanly
                preexec_fn=os.setsid if os.name != "nt" else None,
            )
        except Exception as exc:
            self._cleanup_tmp()
            raise RuntimeError(f"failed to launch suricata: {exc}") from exc

        self.started_at = time.time()
        self._tailer = threading.Thread(
            target=self._tail_loop,
            args=(log_dir / "eve.json",),
            daemon=True,
            name="nade-suricata-tail",
        )
        self._tailer.start()

    def stop(self) -> None:
        self._stop_event.set()
        with self._lock:
            proc = self._proc
            self._proc = None
        if proc is not None:
            already_dead = proc.poll() is not None
            if not already_dead:
                try:
                    if os.name != "nt":
                        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                    else:
                        proc.terminate()
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    try:
                        proc.kill()
                    except Exception:
                        pass
                except ProcessLookupError:
                    pass  # raced — already gone
                except Exception as exc:
                    log.warning("suricata stop raised: %s", exc)
        # final stderr snapshot from the file
        self._refresh_stderr()
        if self._stderr_fh is not None:
            try:
                self._stderr_fh.close()
            except Exception:
                pass
            self._stderr_fh = None
        if self._tailer and self._tailer.is_alive():
            self._tailer.join(timeout=3)
        self._cleanup_tmp()

    def is_running(self) -> bool:
        return bool(self._proc and self._proc.poll() is None)

    def status(self) -> dict:
        # Refresh stderr tail / classified error on every status request so
        # the UI sees errors as soon as Suricata logs them, not only after
        # the user clicks Stop.
        self._refresh_stderr()
        return {
            "running": self.is_running(),
            "binary": self.binary,
            "interface": self.interface,
            "rules": len(self.rule_texts),
            "alert_count": self.alert_count,
            "started_at": self.started_at,
            "error": self.error,
            "stderr_tail": self.stderr_tail or None,
        }

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _cleanup_tmp(self) -> None:
        tmp = self._tmp
        self._tmp = None
        self._stderr_path = None
        if tmp is not None:
            try:
                tmp.cleanup()
            except Exception as exc:  # pragma: no cover
                log.debug("temp cleanup failed: %s", exc)

    # Patterns that indicate Suricata can't capture for permission reasons.
    # We elevate these to the user-visible `error` field so the UI doesn't
    # leave the user wondering why no alerts are firing.
    _PERM_PATTERNS = (
        "unable to set caps",
        "operation not permitted",
        "permission denied",
        "you don't have permission",
        "failed to find iface",
        "could not get info on",
    )

    def _refresh_stderr(self) -> None:
        path = self._stderr_path
        if path is None or not path.exists():
            return
        try:
            data = path.read_bytes()
        except OSError:
            return
        text = data.decode(errors="replace")
        # keep only the tail to bound memory in long-running sessions
        self.stderr_tail = text[-4000:]
        low = text.lower()
        if any(pat in low for pat in self._PERM_PATTERNS):
            self.error = (
                "Suricata cannot capture on this interface (permission denied). "
                "Restart the backend with sudo, or grant cap_net_admin / cap_net_raw "
                "to the suricata binary, then try again."
            )
        elif "error:" in low and not self.error:
            # surface the first ERROR line so the user sees something useful
            for line in text.splitlines():
                if "error:" in line.lower():
                    self.error = line.strip()[:300]
                    break

    def _tail_loop(self, eve_path: Path) -> None:
        # Wait for suricata to create eve.json. If it never appears, surface
        # whatever it printed to stderr.
        deadline = time.time() + self.EVE_WAIT_SEC
        while not eve_path.exists() and not self._stop_event.is_set():
            if self._proc is None or self._proc.poll() is not None:
                self._refresh_stderr()
                if not self.error:
                    self.error = "suricata exited before producing eve.json"
                return
            if time.time() > deadline:
                self._refresh_stderr()
                if not self.error:
                    self.error = "timed out waiting for suricata eve.json"
                return
            time.sleep(0.25)

        if self._stop_event.is_set():
            return

        try:
            f = eve_path.open("r", encoding="utf-8", errors="replace")
        except Exception as exc:
            self.error = f"failed to open eve.json: {exc}"
            return

        buf = ""
        try:
            while not self._stop_event.is_set():
                chunk = f.read()
                if not chunk:
                    # process may have died — check
                    if self._proc is None or self._proc.poll() is not None:
                        # final pass after death, then exit
                        chunk = f.read()
                        if chunk:
                            buf += chunk
                        self._consume_lines(buf)
                        return
                    time.sleep(self.TAIL_IDLE_SLEEP)
                    continue
                buf += chunk
                # consume complete lines
                while "\n" in buf:
                    line, buf = buf.split("\n", 1)
                    self._handle_eve_line(line)
        finally:
            try:
                f.close()
            except Exception:
                pass

    def _consume_lines(self, buf: str) -> None:
        for line in buf.splitlines():
            self._handle_eve_line(line)

    def _handle_eve_line(self, line: str) -> None:
        line = line.strip()
        if not line:
            return
        try:
            ev = json.loads(line)
        except ValueError:
            return
        a = eve_event_to_alert(ev)
        if a is None:
            return
        try:
            with SessionLocal() as db:
                db.add(
                    models.Alert(
                        upload_id=self.upload_id,
                        ts=a.ts or time.time(),
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
            self.alert_count += 1
        except Exception as exc:  # pragma: no cover
            log.warning("failed to persist live suricata alert: %s", exc)

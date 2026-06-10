"""Suricata rule execution engine.

Two backends:

1. **External Suricata** — used automatically when the ``suricata`` binary is
   on PATH (or ``NADE_SURICATA_BIN`` is set). We write enabled rules to a
   temp file, run ``suricata -r <pcap> -l <out> -S <rules>`` with EVE JSON
   logging, then parse alerts from ``<out>/eve.json``.

2. **Python emulator** — fallback that interprets the subset of rule options
   used by NADE's bundled rules against `ParsedPacket` objects.

Both paths return ``DetectionAlert`` instances tagged with category
``suricata:<rule_category_or_classtype>`` so they integrate naturally with
the existing reporting / dashboard pipeline.
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import tempfile
from collections import defaultdict
from pathlib import Path

from backend.detectors.base import DetectionAlert
from backend.parsers import ParsedPacket, parse_pcap

from .parser import ParsedRule, parse_rule

log = logging.getLogger(__name__)


def suricata_binary() -> str | None:
    explicit = os.environ.get("NADE_SURICATA_BIN")
    if explicit and Path(explicit).exists():
        return explicit
    return shutil.which("suricata")


# ---------------------------------------------------------------------------
# Python emulator
# ---------------------------------------------------------------------------


def _proto_matches(rule: ParsedRule, pkt: ParsedPacket) -> bool:
    rp = rule.proto
    pp = pkt.protocol
    if rp == "ip":
        return pp in {"IP", "IPv6", "TCP", "UDP", "ICMP", "DNS"}
    if rp == "tcp":
        return pp == "TCP"
    if rp == "udp":
        return pp in {"UDP", "DNS"}
    if rp == "dns":
        return pp == "DNS"
    if rp == "icmp":
        return pp == "ICMP"
    return False


def _flags_match(rule: ParsedRule, pkt: ParsedPacket) -> bool:
    if not rule.flags_required and not rule.flags_forbidden:
        return True
    flags = set(pkt.tcp_flags or "")
    if not rule.flags_required.issubset(flags):
        return False
    if rule.flags_forbidden & flags:
        return False
    return True


def _dsize_match(rule: ParsedRule, pkt: ParsedPacket) -> bool:
    if rule.dsize_op is None:
        return True
    val = rule.dsize_val or 0
    L = pkt.length
    return {
        ">": L > val, "<": L < val, "=": L == val,
        ">=": L >= val, "<=": L <= val,
    }[rule.dsize_op]


def _packet_matches(rule: ParsedRule, pkt: ParsedPacket) -> bool:
    if not _proto_matches(rule, pkt):
        return False
    if not rule.src_port.matches(pkt.src_port):
        return False
    if not rule.dst_port.matches(pkt.dst_port):
        return False
    if not _flags_match(rule, pkt):
        return False
    if not _dsize_match(rule, pkt):
        return False
    return True


def _evaluate_rule_emulated(rule: ParsedRule, packets: list[ParsedPacket]) -> list[DetectionAlert]:
    matches = [p for p in packets if _packet_matches(rule, p)]
    if not matches:
        return []

    severity = _severity_for(rule)
    category_tag = f"suricata:{_short_category(rule)}"
    alerts: list[DetectionAlert] = []

    if rule.threshold:
        # Sliding window: emit ONE alert per tracker key when count is reached.
        key_fn = (lambda p: p.src_ip) if rule.threshold.track == "by_src" else (lambda p: p.dst_ip)
        groups: dict[str, list[ParsedPacket]] = defaultdict(list)
        for p in matches:
            k = key_fn(p) or ""
            groups[k].append(p)

        for key, plist in groups.items():
            plist.sort(key=lambda p: p.ts)
            i = 0
            for j in range(len(plist)):
                while plist[j].ts - plist[i].ts > rule.threshold.seconds:
                    i += 1
                count = j - i + 1
                if count >= rule.threshold.count:
                    first = plist[i]
                    alerts.append(
                        DetectionAlert(
                            ts=first.ts,
                            severity=severity,
                            category=category_tag,
                            title=f"[SID {rule.sid}] {rule.msg}",
                            description=(
                                f"Threshold reached: {count} matches "
                                f"({rule.threshold.track}={key}) within "
                                f"{rule.threshold.seconds}s."
                            ),
                            src_ip=first.src_ip,
                            dst_ip=first.dst_ip,
                            mitre_id=rule.mitre_id,
                            evidence={
                                "sid": rule.sid,
                                "rev": rule.rev,
                                "classtype": rule.classtype,
                                "engine": "nade-emulator",
                                "track": rule.threshold.track,
                                "tracker_value": key,
                                "matches_in_window": count,
                                "window_sec": rule.threshold.seconds,
                                "rule": rule.raw[:512],
                            },
                        )
                    )
                    break  # one alert per tracker key
        return alerts

    # No threshold: one alert per N matches (cap to avoid noise).
    cap = 25
    for p in matches[:cap]:
        alerts.append(
            DetectionAlert(
                ts=p.ts,
                severity=severity,
                category=category_tag,
                title=f"[SID {rule.sid}] {rule.msg}",
                description=f"Packet matched rule {rule.sid}.",
                src_ip=p.src_ip,
                dst_ip=p.dst_ip,
                mitre_id=rule.mitre_id,
                evidence={
                    "sid": rule.sid,
                    "rev": rule.rev,
                    "classtype": rule.classtype,
                    "engine": "nade-emulator",
                    "src_port": p.src_port,
                    "dst_port": p.dst_port,
                    "rule": rule.raw[:512],
                },
            )
        )
    if len(matches) > cap:
        alerts[-1].evidence["truncated_match_count"] = len(matches)
    return alerts


def _severity_for(rule: ParsedRule) -> str:
    ct = (rule.classtype or "").lower()
    if "dos" in ct or "trojan" in ct or "shellcode" in ct or "exploit" in ct:
        return "high"
    if "user" in ct:
        return "medium"
    if "recon" in ct:
        return "medium"
    return "low"


def _short_category(rule: ParsedRule) -> str:
    msg = (rule.msg or "").lower()
    for needle, label in (
        ("port scan", "port_scan"),
        ("syn flood", "syn_flood"),
        ("dns tunnel", "dns_tunneling"),
        ("brute force", "brute_force"),
        ("beacon", "beaconing"),
        ("arp", "arp_spoofing"),
        ("malware", "malware_traffic"),
    ):
        if needle in msg:
            return label
    return rule.classtype or "rule"


# ---------------------------------------------------------------------------
# External Suricata runner
# ---------------------------------------------------------------------------


def eve_event_to_alert(ev: dict) -> DetectionAlert | None:
    """Convert one parsed Suricata EVE JSON event into a DetectionAlert.

    Returns None for non-alert events (flow, stats, dns, http, ...).
    Used by both the offline runner and the live IDS tailer.
    """
    if ev.get("event_type") != "alert":
        return None
    sig = ev.get("alert", {})
    ts = ev.get("timestamp", 0)
    try:
        from datetime import datetime
        ts_f = datetime.fromisoformat(str(ts).replace("Z", "+00:00")).timestamp()
    except Exception:
        ts_f = 0.0

    return DetectionAlert(
        ts=ts_f,
        severity="high" if sig.get("severity", 3) <= 2 else "medium",
        category=f"suricata:{sig.get('category', 'rule').replace(' ', '_').lower()}",
        title=f"[SID {sig.get('signature_id')}] {sig.get('signature', '')}",
        description=sig.get("category", ""),
        src_ip=ev.get("src_ip"),
        dst_ip=ev.get("dest_ip"),
        mitre_id=_mitre_from_metadata(sig.get("metadata", {})),
        evidence={
            "sid": sig.get("signature_id"),
            "rev": sig.get("rev"),
            "classtype": sig.get("category"),
            "engine": "suricata",
            "src_port": ev.get("src_port"),
            "dst_port": ev.get("dest_port"),
            "proto": ev.get("proto"),
        },
    )


def _run_external(pcap_path: str, rule_texts: list[str], binary: str) -> list[DetectionAlert]:
    with tempfile.TemporaryDirectory() as tmp:
        rules_file = Path(tmp) / "nade.rules"
        out_dir = Path(tmp) / "out"
        out_dir.mkdir()
        rules_file.write_text("\n".join(rule_texts) + "\n")

        cmd = [
            binary, "-r", pcap_path, "-l", str(out_dir),
            "-S", str(rules_file),
            "--runmode=single",
            "-k", "none",
        ]
        log.info("Running Suricata: %s", " ".join(cmd))
        try:
            subprocess.run(cmd, check=False, timeout=300, capture_output=True)
        except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
            log.warning("Suricata invocation failed: %s", exc)
            return []

        eve = out_dir / "eve.json"
        if not eve.exists():
            return []

        alerts: list[DetectionAlert] = []
        for line in eve.read_text().splitlines():
            try:
                ev = json.loads(line)
            except ValueError:
                continue
            a = eve_event_to_alert(ev)
            if a is not None:
                alerts.append(a)
        return alerts


def _mitre_from_metadata(meta: dict | list) -> str | None:
    items: list[str] = []
    if isinstance(meta, dict):
        items = meta.get("mitre", []) or []
    elif isinstance(meta, list):
        items = [m for m in meta if isinstance(m, str)]
    for item in items:
        m = str(item).strip().split()
        if m and m[0].lower() == "mitre" and len(m) > 1:
            return m[1]
        if str(item).startswith("T") and any(ch.isdigit() for ch in str(item)):
            return str(item)
    return None


# ---------------------------------------------------------------------------
# Public entrypoint
# ---------------------------------------------------------------------------


def run_rules(pcap_path: str, rule_rows: list) -> tuple[list[DetectionAlert], dict]:
    """Run *enabled* rules against the PCAP at *pcap_path*.

    `rule_rows` is an iterable of ORM SuricataRule (or dict-likes) with
    ``rule_text`` and ``enabled`` attributes.
    """
    rule_texts = [r.rule_text for r in rule_rows if getattr(r, "enabled", True)]
    if not rule_texts:
        return [], {"engine": "none", "rules": 0, "alerts": 0}

    binary = suricata_binary()
    if binary:
        alerts = _run_external(pcap_path, rule_texts, binary)
        meta = {"engine": "suricata", "binary": binary, "rules": len(rule_texts), "alerts": len(alerts)}
        return alerts, meta

    parsed_rules: list[ParsedRule] = []
    for txt in rule_texts:
        pr = parse_rule(txt)
        if pr:
            parsed_rules.append(pr)
    packets = list(parse_pcap(pcap_path))
    alerts: list[DetectionAlert] = []
    for pr in parsed_rules:
        alerts.extend(_evaluate_rule_emulated(pr, packets))
    meta = {
        "engine": "nade-emulator",
        "rules_total": len(rule_texts),
        "rules_evaluated": len(parsed_rules),
        "alerts": len(alerts),
    }
    return alerts, meta

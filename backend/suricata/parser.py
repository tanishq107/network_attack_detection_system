"""Tiny Suricata rule parser.

Supports the subset of options used by NADE's bundled rules:
- header: ``alert <proto> <src> <sport> -> <dst> <dport>``
- options: ``msg``, ``sid``, ``rev``, ``classtype``, ``flags``, ``dsize``,
  ``threshold`` (type both, track by_src|by_dst, count N, seconds N),
  ``metadata`` (mitre <ID>), ``flow`` (ignored).
- ports: ``any``, ``80``, ``[80,443,8080]``, ``!22`` (negation), ``1024:`` ranges.

Anything unknown is preserved in `unknown` for transparency but does not
cause a parse failure — rules can still be displayed/edited in the GUI even
if our emulator can't fully evaluate them. They will still run correctly when
delegated to a real Suricata binary.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable


@dataclass
class PortSpec:
    raw: str
    any: bool = False
    negate: bool = False
    values: set[int] = field(default_factory=set)
    range: tuple[int | None, int | None] | None = None  # (lo, hi)

    def matches(self, port: int | None) -> bool:
        if self.any:
            return True
        if port is None:
            return False
        hit = False
        if self.values and port in self.values:
            hit = True
        if self.range:
            lo, hi = self.range
            if (lo is None or port >= lo) and (hi is None or port <= hi):
                hit = True
        return (not hit) if self.negate else hit


@dataclass
class Threshold:
    type: str = "both"  # both|threshold|limit
    track: str = "by_src"  # by_src|by_dst
    count: int = 1
    seconds: int = 60


@dataclass
class ParsedRule:
    sid: int
    msg: str
    proto: str  # tcp|udp|icmp|ip|dns
    src_port: PortSpec
    dst_port: PortSpec
    flags_required: set[str] = field(default_factory=set)
    flags_forbidden: set[str] = field(default_factory=set)
    dsize_op: str | None = None    # >, <, =, >=, <=
    dsize_val: int | None = None
    threshold: Threshold | None = None
    classtype: str | None = None
    mitre_id: str | None = None
    rev: int = 1
    raw: str = ""
    unknown: list[str] = field(default_factory=list)


_HEADER_RE = re.compile(
    r"^\s*alert\s+(?P<proto>\w+)\s+"
    r"(?P<src>\S+)\s+(?P<sport>\S+)\s+"
    r"->\s+"
    r"(?P<dst>\S+)\s+(?P<dport>\S+)\s*"
    r"\((?P<body>.*)\)\s*$",
    re.DOTALL,
)


def _parse_port(raw: str) -> PortSpec:
    spec = PortSpec(raw=raw)
    s = raw.strip()
    if s.startswith("!"):
        spec.negate = True
        s = s[1:]
    if s == "any":
        spec.any = True
        return spec
    if s.startswith("[") and s.endswith("]"):
        items = [x.strip() for x in s[1:-1].split(",") if x.strip()]
    else:
        items = [s]
    for item in items:
        if ":" in item:
            lo_s, hi_s = item.split(":", 1)
            lo = int(lo_s) if lo_s else None
            hi = int(hi_s) if hi_s else None
            spec.range = (lo, hi)
        else:
            try:
                spec.values.add(int(item))
            except ValueError:
                # symbolic like $HTTP_PORTS — accept as "any" for emulator.
                spec.any = True
    return spec


_FLAG_LETTERS = {"F", "S", "R", "P", "A", "U", "1", "2"}


def _parse_flags(value: str) -> tuple[set[str], set[str]]:
    """flags:S,12 -> required={S}, forbidden_mask ignored.

    We treat anything left of an optional comma as required flags. Anything
    not in the required set is "must not be set", except bits explicitly
    listed after a comma (legacy "ignore" mask) — those are not enforced.
    """
    required: set[str] = set()
    parts = value.split(",", 1)
    req_part = parts[0]
    if req_part.startswith("+"):
        req_part = req_part[1:]
    for ch in req_part:
        if ch in _FLAG_LETTERS:
            required.add(ch)
    # Forbid the "scan" classics: only require what's listed; ACK forbidden
    # for SYN-only matchers is the most common case in our rules.
    forbidden = {"A"} if required == {"S"} else set()
    return required, forbidden


_DSIZE_RE = re.compile(r"^\s*(>=|<=|>|<|=)?\s*(\d+)\s*$")


def _parse_dsize(value: str) -> tuple[str, int]:
    m = _DSIZE_RE.match(value)
    if not m:
        return "=", 0
    op = m.group(1) or "="
    return op, int(m.group(2))


_THRESH_KV = re.compile(r"(type|track|count|seconds)\s+([^\s,]+)")


def _parse_threshold(value: str) -> Threshold:
    t = Threshold()
    for k, v in _THRESH_KV.findall(value):
        if k == "type":
            t.type = v
        elif k == "track":
            t.track = v
        elif k == "count":
            t.count = int(v)
        elif k == "seconds":
            t.seconds = int(v)
    return t


def _split_options(body: str) -> Iterable[tuple[str, str]]:
    # Split on `;` but respect quoted strings.
    buf, in_q = [], False
    parts: list[str] = []
    for ch in body:
        if ch == '"':
            in_q = not in_q
            buf.append(ch)
        elif ch == ";" and not in_q:
            parts.append("".join(buf).strip())
            buf = []
        else:
            buf.append(ch)
    if buf:
        parts.append("".join(buf).strip())

    for p in parts:
        if not p:
            continue
        if ":" in p:
            k, v = p.split(":", 1)
            yield k.strip().lower(), v.strip().strip('"')
        else:
            yield p.strip().lower(), ""


def parse_rule(rule_text: str) -> ParsedRule | None:
    """Return a ParsedRule, or None if the line isn't an alert rule we recognise."""
    text = rule_text.strip()
    if not text or text.startswith("#"):
        return None
    m = _HEADER_RE.match(text)
    if not m:
        return None

    proto = m.group("proto").lower()
    rule = ParsedRule(
        sid=0,
        msg="",
        proto=proto,
        src_port=_parse_port(m.group("sport")),
        dst_port=_parse_port(m.group("dport")),
        raw=text,
    )

    for key, value in _split_options(m.group("body")):
        if key == "msg":
            rule.msg = value
        elif key == "sid":
            try:
                rule.sid = int(value)
            except ValueError:
                pass
        elif key == "rev":
            try:
                rule.rev = int(value)
            except ValueError:
                pass
        elif key == "classtype":
            rule.classtype = value
        elif key == "flags":
            req, forb = _parse_flags(value)
            rule.flags_required = req
            rule.flags_forbidden = forb
        elif key == "dsize":
            rule.dsize_op, rule.dsize_val = _parse_dsize(value)
        elif key == "threshold":
            rule.threshold = _parse_threshold(value)
        elif key == "metadata":
            mm = re.search(r"mitre\s+([A-Za-z0-9.]+)", value)
            if mm:
                rule.mitre_id = mm.group(1)
        elif key in {"flow", "rev", "reference", "priority"}:
            continue  # not needed by emulator
        else:
            rule.unknown.append(f"{key}:{value}")

    return rule

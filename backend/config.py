"""Runtime configuration."""
from __future__ import annotations

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("NADE_DATA_DIR", BASE_DIR / "data"))
UPLOAD_DIR = DATA_DIR / "uploads"
REPORT_DIR = DATA_DIR / "reports"

DATA_DIR.mkdir(parents=True, exist_ok=True)
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
REPORT_DIR.mkdir(parents=True, exist_ok=True)

DATABASE_URL = os.environ.get(
    "NADE_DATABASE_URL",
    f"sqlite:///{DATA_DIR / 'nade.db'}",
)

# Detection thresholds (tunable via env)
PORT_SCAN_UNIQUE_PORTS = int(os.environ.get("NADE_PORTSCAN_PORTS", "20"))
PORT_SCAN_WINDOW_SEC = int(os.environ.get("NADE_PORTSCAN_WINDOW", "10"))
SYN_FLOOD_RATE = int(os.environ.get("NADE_SYNFLOOD_RATE", "100"))  # syns / sec
SYN_FLOOD_WINDOW_SEC = int(os.environ.get("NADE_SYNFLOOD_WINDOW", "5"))
DNS_TUNNEL_QNAME_LEN = int(os.environ.get("NADE_DNS_QLEN", "50"))
DNS_TUNNEL_QPS = int(os.environ.get("NADE_DNS_QPS", "20"))
BRUTE_FORCE_ATTEMPTS = int(os.environ.get("NADE_BRUTE_ATTEMPTS", "15"))
BRUTE_FORCE_WINDOW_SEC = int(os.environ.get("NADE_BRUTE_WINDOW", "60"))
BEACON_MIN_CONNECTIONS = int(os.environ.get("NADE_BEACON_MIN", "8"))
BEACON_JITTER_RATIO = float(os.environ.get("NADE_BEACON_JITTER", "0.20"))
# Common ports that legit apps frequently poll (HTTPS APIs, mail, DB, RDP).
# Beaconing on these is too noisy to be useful by default — set
# NADE_BEACON_INCLUDE_STANDARD=1 to disable the filter.
BEACON_STANDARD_PORTS: frozenset[int] = frozenset({
    80, 443, 22, 53, 25, 110, 143, 465, 587, 993, 995,
    3306, 3389, 5432, 6379, 27017,
})
BEACON_INCLUDE_STANDARD = os.environ.get("NADE_BEACON_INCLUDE_STANDARD", "0") == "1"

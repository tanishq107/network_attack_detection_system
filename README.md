# NADE — Network Attack Detection Engine

A self-contained network security analytics platform that ingests **PCAP files**
or **live traffic**, runs a hybrid detection stack (Python heuristics + the
real **Suricata** IDS), maps findings to **MITRE ATT&CK**, and produces
**JSON / HTML / PDF** reports through a modern React dashboard with light and
dark themes.

```
N · A · D · E
NETWORK   ATTACK   DETECTION   ENGINE
```

---

## Highlights

- **PCAP upload + live sniffer** — pick an interface, set an optional BPF
  filter, and watch alerts appear in real time. Captured traffic can be
  downloaded as a PCAP afterwards.
- **Hybrid detection** — Python detectors (port scan, SYN flood, DNS tunneling,
  brute force, beaconing, ARP spoof, malware traffic) run alongside the real
  Suricata IDS for signature-based coverage.
- **Suricata rules manager** — view bundled rules, write your own, or import
  from a URL / pasted text. Toggle individual rules on or off.
- **Reports** — executive summary, IOC list, MITRE technique mapping,
  per-alert detail. Rendered as HTML, downloadable as JSON or PDF.
- **Dashboard** — totals, severity doughnut, category bar chart, alert
  timeline, per-alert table with severity pills. Charts re-theme with the UI.
- **Light / dark themes** — persisted in `localStorage`, applied before React
  mounts so there is no flash. Animated SVG network-mesh logo with a glowing
  "N" and a packet pulsing along its diagonal.

---

## Tech stack

| Layer    | Tools                                                       |
| -------- | ----------------------------------------------------------- |
| Backend  | Python 3.14 · FastAPI · Scapy · SQLAlchemy · SQLite         |
| IDS      | Suricata 7 (subprocess + `eve.json` tailer)                 |
| Reports  | Jinja2 (HTML) · WeasyPrint (PDF) · stdlib `json`            |
| Frontend | React 18 · Vite 5 · Tailwind CSS 3 · Chart.js 4             |
| Tests    | pytest                                                      |

---

## Project layout

```
backend/
  api/main.py            FastAPI app + all REST endpoints
  parsers/               PCAP → packets / flows  (Scapy PcapReader)
  detectors/             Python detection modules
  analyzers/             Summary, timeline, aggregation
  threatintel/           IOC enrichment hooks
  reports/               HTML / JSON / PDF report generators
  live/
    sniffer.py           Live AsyncSniffer + PcapWriter recording
    suricata_live.py     Suricata subprocess + eve.json tailer
  suricata/              Bundled rules + suricata.yaml template
  database/              SQLAlchemy models & session factory
  data/                  SQLite DB + stored uploads (gitignored)
  tests/                 Detector unit tests

frontend/
  index.html             Title, favicon, pre-React no-flash theme script
  tailwind.config.js     darkMode 'class' + brand palette
  src/
    App.jsx              Header (logo + theme toggle + upload), tabs,
                         dashboard, alert table, Chart.js wiring
    RulesView.jsx        Suricata rules CRUD + import + filter
    LiveView.jsx         Live sniffer controls + status + alerts
    useTheme.js          Light/dark hook (localStorage-backed)
    index.css            Tailwind layers + .nade-* component classes

docker/                  Optional Dockerfiles + compose
docs/architecture.md     System diagram and "add a detector" guide
sample_pcaps/            Drop test PCAPs here (gitignored)
```

---

## Quick start

### 1. Backend

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# macOS
brew install suricata
# Debian/Ubuntu
sudo apt install suricata

uvicorn api.main:app --reload --port 8000
```

Interactive API docs at **http://localhost:8000/docs**.

> **Live sniffer requires raw-socket privileges.** Run uvicorn with `sudo`, or
> grant the Python binary `cap_net_raw` on Linux:
>
> ```bash
> sudo setcap cap_net_raw,cap_net_admin=eip "$(readlink -f "$(which python3)")"
> ```

### 2. Frontend

```bash
cd frontend
npm install
npm run dev          # http://localhost:5173 (proxies /api → :8000)
```

Production build:

```bash
npm run build        # output in frontend/dist
```

### 3. Try it from the CLI

```bash
curl -F "file=@sample_pcaps/example.pcap" http://localhost:8000/api/upload
curl http://localhost:8000/api/alerts
curl http://localhost:8000/api/summary
curl -OJ "http://localhost:8000/api/report/1?format=html"
```

---

## REST API

### Uploads
| Method   | Path                                | Description                          |
| -------- | ----------------------------------- | ------------------------------------ |
| `POST`   | `/api/upload`                       | multipart PCAP upload                |
| `GET`    | `/api/uploads`                      | list uploads                         |
| `DELETE` | `/api/uploads/{id}`                 | cascade delete + remove stored file  |
| `GET`    | `/api/uploads/{id}/download`        | stream the stored PCAP               |

### Analytics
| Method | Path                                                  |
| ------ | ----------------------------------------------------- |
| `GET`  | `/api/alerts?upload_id=&limit=`                       |
| `GET`  | `/api/summary?upload_id=`                             |
| `GET`  | `/api/timeline?upload_id=&buckets=`                   |

### Reports
| Method | Path                                                    |
| ------ | ------------------------------------------------------- |
| `GET`  | `/api/report/{upload_id}?format=html\|json\|pdf`        |

### Suricata rules
| Method   | Path                          | Description                       |
| -------- | ----------------------------- | --------------------------------- |
| `GET`    | `/api/rules`                  | list                              |
| `POST`   | `/api/rules`                  | create custom rule                |
| `PATCH`  | `/api/rules/{id}`             | enable / disable                  |
| `DELETE` | `/api/rules/{id}`             | delete (non-bundled only)         |
| `POST`   | `/api/rules/import`           | `{ url? , text? , source_label }` |
| `POST`   | `/api/rules/run/{upload_id}`  | run Suricata on a stored PCAP     |

### Live sniffer
| Method | Path                    | Description                                  |
| ------ | ----------------------- | -------------------------------------------- |
| `GET`  | `/api/live/interfaces`  | list available NICs                          |
| `GET`  | `/api/live/status`      | current sniffer + Suricata state             |
| `POST` | `/api/live/start`       | `{ interface, bpf_filter?, with_suricata }`  |
| `POST` | `/api/live/stop`        | stop + finalize PCAP recording               |

---

## Detection modules

| Module             | Detects                                                   |
| ------------------ | --------------------------------------------------------- |
| `port_scan`        | High fan-out of unique destination ports from one source  |
| `syn_flood`        | High-rate TCP SYN bursts to a single target               |
| `dns_tunneling`    | Long / high-entropy DNS labels, oversized TXT             |
| `brute_force`      | Repeated auth attempts (SSH, FTP, RDP, HTTP basic)        |
| `beaconing`        | Periodic outbound connections (standard ports filtered)   |
| `arp_spoof`        | Multiple MACs claiming the same IP                        |
| `malware_traffic`  | IOC-list match (domains / IPs / JA3)                      |

Each detector returns alerts with severity, MITRE technique ID, and evidence.

### Adding a detector
1. Create `backend/detectors/my_thing.py` exposing a class with `name` and
   `detect(packets)`.
2. Add a MITRE entry in `backend/detectors/mitre_map.py`.
3. Register it in `all_detectors()` inside `backend/detectors/__init__.py`.
4. Add tests in `backend/tests/test_detectors.py`.

---

## Database

SQLite file at `backend/data/nade.db` (auto-created on first run).

| Table     | Key columns                                                                 |
| --------- | --------------------------------------------------------------------------- |
| `uploads` | `id, filename, path, status, packet_count, created_at`                      |
| `packets` | `upload_id, ts, src_ip, dst_ip, proto, sport, dport, len`                   |
| `flows`   | `upload_id, 5-tuple, first_ts, last_ts, byte counts`                        |
| `alerts`  | `upload_id, ts, severity, category, title, src_ip, dst_ip, mitre_id, evidence` |
| `rules`   | `sid, name, category, source, enabled, mitre_id, rule_text`                 |

Suricata alerts are categorized as `suricata:<sig_name>` so a re-run can purge
prior Suricata alerts for the same upload before re-inserting (no duplicates).

---

## Configuration

| Variable                          | Purpose                                             |
| --------------------------------- | --------------------------------------------------- |
| `NADE_DATABASE_URL`               | Override SQLite path or use PostgreSQL              |
| `NADE_SURICATA_BIN`               | Explicit path to the `suricata` binary              |
| `NADE_BEACON_INCLUDE_STANDARD`    | Set to `1` to include 80/443/22/53/… in beaconing   |

---

## Testing

```bash
cd backend
pytest -q
```

Recommended datasets: **CICIDS2017**, **malware-traffic-analysis.net** PCAPs.

---

## Docker (optional)

```bash
docker compose -f docker/docker-compose.yml up --build
```

---

## Troubleshooting

- **Live sniffer fails with "permission denied" / "unable to set caps"** —
  run uvicorn with `sudo` or grant `cap_net_raw` (see Quick Start). The UI
  shows a red banner with the exact command.
- **Re-running Suricata duplicates alerts** — fixed; prior `suricata:%`
  rows for the same upload are deleted before re-insert.
- **`Download PCAP` returns `409`** — a live session is still recording to
  that file. Stop it first.
- **Refresh button "does nothing"** — every list endpoint is cache-busted
  (`?_=<ts>` + `cache: 'no-store'`); use the per-tab Refresh button which
  has its own spinner independent of background polling.

---

## License

MIT — see [LICENSE](LICENSE).

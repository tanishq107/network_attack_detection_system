<p align="center">
  <img src="docs/logo.svg" alt="NADE — Network Attack Detection Engine" width="520">
</p>

# NADE — Network Attack Detection Engine

A self-contained network security analytics platform that ingests **PCAP files**
or **live traffic**, runs a hybrid detection stack (Python heuristics + the
real **Suricata** IDS), maps findings to **MITRE ATT&CK**, and produces
**JSON / HTML / PDF** reports through a modern React dashboard with light and
dark themes.


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

cd ..
sudo backend/.venv/bin/uvicorn backend.api.main:app --reload --port 8000
```

Interactive API docs at **http://localhost:8000/docs**.

> **Live sniffer requires raw-socket privileges.** Run uvicorn with `sudo`, or
> grant the Python binary `cap_net_raw` on Linux:
>
> ```bash
> sudo setcap cap_net_raw,cap_net_admin=eip "$(readlink -f "$(which python3)")"
> ```

### 2. Frontend

The dashboard needs **Node.js 18+** (which ships `npm`). If it isn't already
installed, install it once per machine:

```bash
# macOS (Homebrew)
brew install node

# Debian / Ubuntu
sudo apt update && sudo apt install -y nodejs npm

# Windows (winget)
winget install OpenJS.NodeJS.LTS

# Or via nvm (any OS) — recommended for managing multiple Node versions
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh | bash
# restart your shell, then:
nvm install --lts
```

Verify:

```bash
node -v        # should print v18.x or newer
npm  -v
```

Then install the project's JS dependencies and start the dev server:

```bash
cd frontend
npm install
npm run dev          # http://localhost:5173 (proxies /api → :8000)
```

Production build:

```bash
npm run build        # output in frontend/dist
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

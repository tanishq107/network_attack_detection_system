# Architecture

## Offline analysis (uploaded PCAP)

```
┌──────────┐    upload    ┌───────────────┐    parse    ┌──────────────┐
│ Frontend ├─────────────►│ FastAPI /api  ├────────────►│ Scapy parser │
│ (React)  │              │  /upload      │             └──────┬───────┘
└────┬─────┘              │  /alerts      │                    │
     │ fetch              │  /summary     │              ParsedPackets
     ▼                    │  /timeline    │                    │
  Dashboard               │  /report      │                    ▼
                          └──────┬────────┘            ┌───────────────┐
                                 │                     │  Flow builder │
                                 │ persist             └──────┬────────┘
                                 ▼                            │
                          ┌──────────────┐                    ▼
                          │ SQLAlchemy   │           ┌────────────────┐
                          │  uploads     │           │ Python         │
                          │  packets     │◄──alerts──┤ detectors      │
                          │  flows       │           │  port_scan     │
                          │  alerts      │           │  syn_flood     │
                          │  rules       │           │  dns_tunneling │
                          └──────┬───────┘           │  brute_force   │
                                 │                   │  beaconing     │
                                 │                   │  arp_spoof     │
                                 │                   │  malware       │
                                 │                   └────────────────┘
                                 │
                                 │       on demand
                                 ▼
                          ┌──────────────┐           ┌────────────────┐
                          │  Suricata    │──alerts──►│  MITRE map +   │
                          │  subprocess  │           │  threat-intel  │
                          │  (eve.json)  │           └───────┬────────┘
                          └──────────────┘                   │
                                                             ▼
                                                    ┌────────────────┐
                                                    │ Reports (JSON, │
                                                    │  HTML, PDF)    │
                                                    └────────────────┘
```

## Live capture pipeline

```
┌──────────┐  /live/start  ┌──────────────────┐  scapy.AsyncSniffer
│ Frontend ├──────────────►│  LiveSniffer     ├─────────────┐
│ (React)  │               │  singleton       │             │
└────┬─────┘               └────────┬─────────┘             ▼
     │ poll /live/status            │              ┌────────────────┐
     ▼                              │              │ rolling 60s    │
  LiveView (dashboard)              │              │ packet buffer  │
                                    │              └────────┬───────┘
                                    │                       │
                  PcapWriter ◄──────┘                       ▼
              (data/uploads/live-*.pcap)          ┌────────────────┐
                                                  │ Python         │
                                                  │ detectors      │
                                                  │ every 2s       │
                                                  └────────┬───────┘
                                                           │ alerts
                  optional concurrent Suricata             │
                  ┌─────────────────────────────┐          │
                  │ suricata -i <iface>         │──alerts──┤
                  │ tail eve.json               │          │
                  └─────────────────────────────┘          ▼
                                                  ┌────────────────┐
                                                  │   SQLite       │
                                                  └────────────────┘
```

After `/live/stop`, the recorded PCAP is preserved as a regular upload row, so
it appears in the Dashboard tab and is downloadable via
`GET /api/uploads/{id}/download`.

## Adding a detector

1. Create `backend/detectors/my_thing.py` exposing a class with `name` and
   `detect(packets)` returning a list of `Alert(...)`.
2. Add a MITRE entry in
   [backend/detectors/mitre_map.py](../backend/detectors/mitre_map.py).
3. Register it in `all_detectors()` inside
   [backend/detectors/__init__.py](../backend/detectors/__init__.py).
4. Add tests in
   [backend/tests/test_detectors.py](../backend/tests/test_detectors.py).

## Switching to PostgreSQL

```bash
export NADE_DATABASE_URL=postgresql+psycopg2://nade:nade@localhost:5432/nade
pip install psycopg2-binary
```

## Frontend theming

- Tailwind is configured with `darkMode: 'class'`; the `dark` class is set on
  `<html>` by `useTheme()` and persisted in `localStorage('nade-theme')`.
- An inline script in [frontend/index.html](../frontend/index.html) applies the
  saved theme before React mounts, eliminating the flash of wrong theme.
- Chart.js `defaults.color` / `defaults.borderColor` are refreshed in an
  effect that depends on the current theme, so any chart in the app stays
  readable on both backgrounds without per-chart wiring.

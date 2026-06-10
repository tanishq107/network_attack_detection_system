"""MITRE ATT&CK technique mapping for detectors."""
from __future__ import annotations

MITRE_MAP: dict[str, dict[str, str]] = {
    "port_scan": {
        "tactic": "Discovery",
        "technique": "Network Service Scanning",
        "id": "T1046",
    },
    "syn_flood": {
        "tactic": "Impact",
        "technique": "Network Denial of Service: Direct Network Flood",
        "id": "T1498.001",
    },
    "dns_tunneling": {
        "tactic": "Command and Control",
        "technique": "Application Layer Protocol: DNS",
        "id": "T1071.004",
    },
    "brute_force": {
        "tactic": "Credential Access",
        "technique": "Brute Force",
        "id": "T1110",
    },
    "beaconing": {
        "tactic": "Command and Control",
        "technique": "Non-Standard Port / Beaconing",
        "id": "T1571",
    },
    "arp_spoofing": {
        "tactic": "Credential Access",
        "technique": "Adversary-in-the-Middle: ARP Cache Poisoning",
        "id": "T1557.002",
    },
    "malware_traffic": {
        "tactic": "Command and Control",
        "technique": "Ingress Tool Transfer",
        "id": "T1105",
    },
}

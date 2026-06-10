"""Bundled Suricata rules covering NADE's 7 detection categories.

These are NADE-authored rules that mirror well-known patterns from public
rulesets (Emerging Threats Open, Snort community). Each rule uses a SID in
the local-rules range (1_000_000+) and is tagged with the corresponding MITRE
technique via the `metadata:` field. They are valid Suricata 6+/7+ syntax and
can be copied straight into a real Suricata deployment.

Use the /api/rules/import endpoint to pull in additional rules from any URL
serving a `.rules` file (e.g. https://rules.emergingthreats.net/open/...).
"""
from __future__ import annotations

DEFAULT_RULES: list[dict] = [
    {
        "sid": 1000001,
        "name": "NADE Port Scan - SYN sweep",
        "category": "port_scan",
        "mitre_id": "T1046",
        "rule_text": (
            'alert tcp any any -> any any ('
            'msg:"NADE Port Scan - SYN sweep"; '
            'flow:stateless; flags:S,12; '
            'threshold: type both, track by_src, count 20, seconds 10; '
            'classtype:attempted-recon; sid:1000001; rev:1; '
            'metadata:mitre T1046;)'
        ),
    },
    {
        "sid": 1000002,
        "name": "NADE SYN Flood against single host",
        "category": "syn_flood",
        "mitre_id": "T1498.001",
        "rule_text": (
            'alert tcp any any -> any any ('
            'msg:"NADE SYN Flood"; '
            'flow:stateless; flags:S,12; '
            'threshold: type both, track by_dst, count 500, seconds 5; '
            'classtype:attempted-dos; sid:1000002; rev:1; '
            'metadata:mitre T1498.001;)'
        ),
    },
    {
        "sid": 1000003,
        "name": "NADE DNS Tunneling - oversized query",
        "category": "dns_tunneling",
        "mitre_id": "T1071.004",
        "rule_text": (
            'alert udp any any -> any 53 ('
            'msg:"NADE DNS Tunneling - oversized query"; '
            'dsize:>200; '
            'classtype:trojan-activity; sid:1000003; rev:1; '
            'metadata:mitre T1071.004;)'
        ),
    },
    {
        "sid": 1000004,
        "name": "NADE SSH Brute Force",
        "category": "brute_force",
        "mitre_id": "T1110",
        "rule_text": (
            'alert tcp any any -> any 22 ('
            'msg:"NADE SSH Brute Force"; '
            'flow:stateless; flags:S,12; '
            'threshold: type both, track by_src, count 15, seconds 60; '
            'classtype:attempted-user; sid:1000004; rev:1; '
            'metadata:mitre T1110;)'
        ),
    },
    {
        "sid": 1000005,
        "name": "NADE RDP Brute Force",
        "category": "brute_force",
        "mitre_id": "T1110",
        "rule_text": (
            'alert tcp any any -> any 3389 ('
            'msg:"NADE RDP Brute Force"; '
            'flow:stateless; flags:S,12; '
            'threshold: type both, track by_src, count 15, seconds 60; '
            'classtype:attempted-user; sid:1000005; rev:1; '
            'metadata:mitre T1110;)'
        ),
    },
    {
        "sid": 1000006,
        "name": "NADE Beaconing - high-volume SYN to non-standard ports",
        "category": "beaconing",
        "mitre_id": "T1571",
        # NOTE: Suricata's `threshold` is count-only; it cannot measure the
        # inter-arrival jitter that real beaconing detection requires. The
        # Python BeaconingDetector (backend/detectors/beaconing.py) is the
        # canonical detector — it computes stdev/mean of intervals. This
        # Suricata rule is therefore disabled by default and tightened to
        # high-volume SYNs to non-standard ports only, to keep noise low if
        # an operator chooses to re-enable it.
        "enabled_by_default": False,
        "rule_text": (
            'alert tcp any any -> any '
            '![80,443,22,53,25,110,143,465,587,993,995,3306,3389,5432] ('
            'msg:"NADE Beaconing - high-volume SYN to non-standard ports"; '
            'flow:stateless; flags:S,12; '
            'threshold: type both, track by_src, count 60, seconds 3600; '
            'classtype:trojan-activity; sid:1000006; rev:2; '
            'metadata:mitre T1571;)'
        ),
    },
    {
        "sid": 1000007,
        "name": "NADE Malware - suspicious port (4444 Metasploit)",
        "category": "malware_traffic",
        "mitre_id": "T1105",
        "rule_text": (
            'alert tcp any any -> any 4444 ('
            'msg:"NADE Malware - suspicious port 4444 (Metasploit)"; '
            'flow:stateless; flags:S,12; '
            'classtype:trojan-activity; sid:1000007; rev:1; '
            'metadata:mitre T1105;)'
        ),
    },
    {
        "sid": 1000008,
        "name": "NADE Malware - IRC bot ports 6666-6669",
        "category": "malware_traffic",
        "mitre_id": "T1105",
        "rule_text": (
            'alert tcp any any -> any [6666,6667,6668,6669] ('
            'msg:"NADE Malware - IRC bot port"; '
            'flow:stateless; flags:S,12; '
            'classtype:trojan-activity; sid:1000008; rev:1; '
            'metadata:mitre T1105;)'
        ),
    },
    {
        "sid": 1000009,
        "name": "NADE Malware - elite/back-orifice port 31337",
        "category": "malware_traffic",
        "mitre_id": "T1105",
        "rule_text": (
            'alert tcp any any -> any 31337 ('
            'msg:"NADE Malware - port 31337"; '
            'flow:stateless; flags:S,12; '
            'classtype:trojan-activity; sid:1000009; rev:1; '
            'metadata:mitre T1105;)'
        ),
    },
    {
        "sid": 1000010,
        "name": "NADE ARP - unsolicited reply observed (review)",
        "category": "arp_spoofing",
        "mitre_id": "T1557.002",
        "rule_text": (
            '# NADE rule. Suricata has limited ARP support; the Python ARP '
            'detector remains primary. This stub is kept for documentation. '
            'alert ip any any -> any any (msg:"NADE ARP review"; sid:1000010; rev:1; '
            'metadata:mitre T1557.002;)'
        ),
    },
]

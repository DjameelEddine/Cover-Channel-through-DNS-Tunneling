# DNS Tunneling Detection System

🎉 **Now available on PyPI!** You can now easily install the package as a CLI tool directly using pip.

A simple DNS packet sniffer that captures network traffic and uses a pre-trained ML model to detect malicious DNS queries (DNS tunneling/CoH attacks).

## Quick Start

### 1. Install via pip
```bash
pip install dnssniffer
```
*(This automatically installs all required dependencies and bundles the pre-trained ML model!)*

### 2. Run the Sniffer
Because the tool relies on `scapy` for network capturing, you need Administrator or root privileges.

**Windows (PowerShell - Admin):**
```powershell
dnssniffer
```

**Linux/macOS:**
```bash
sudo dnssniffer
```

### 4. View Results

**Console Output:**
Each captured DNS packet shows:
- Packet number and timestamp
- Source and destination IPs
- Domain name
- Domain length and entropy score
- **Prediction: BENIGN ✓ or MALICIOUS ⚠️**
- Confidence percentage

**CSV Output:**
Results automatically saved to `dns_analysis.csv` with columns:
- Packet number
- Timestamp
- Source/Destination IPs
- Domain name
- Domain characteristics (length, entropy, subdomains)
- Prediction and confidence

## Usage Options

```bash
# Capture unlimited packets (until Ctrl+C)
dnssniffer

# Capture specific number of packets
dnssniffer -c 1000

# Use specific network interface
dnssniffer -i eth0 -c 500

# Both options
dnssniffer -c 100 -i eth0
```

## How It Works

1. **Captures DNS packets** on UDP port 53
2. **Extracts features** from each domain:
   - Domain length
   - Domain entropy (randomness)
   - Number of subdomains
   - Character ratios (digits, special chars)
   - And more...
3. **Uses pre-trained model** (`model.pkl`) to predict: BENIGN or MALICIOUS
4. **Outputs results** to console and `dns_analysis.csv`

## Understanding the Output

### Domain Entropy Score
- **Lower (2-3)**: Normal domains (pronounceable words)
- **Higher (4-5)**: Suspicious (random characters - typical in data encoding)

### Prediction Confidence
- **>90%**: High certainty
- **70-90%**: Medium certainty
- **<70%**: Low certainty

### Example Output
```
[Packet #1] 2024-12-15 14:30:45
  From: 192.168.1.100 → 8.8.8.8
  Domain: google.com
  Length: 10 | Entropy: 2.34
  Prediction: BENIGN ✓ (Confidence: 94%)

[Packet #2] 2024-12-15 14:30:46
  From: 192.168.1.100 → 8.8.8.8
  Domain: aB7cD9eF2xQ4wR8sT1uV5yZ3.tunnel.example.com
  Length: 87 | Entropy: 4.78
  Prediction: MALICIOUS ⚠️ (Confidence: 92%)
```

## CSV File Format

`dns_analysis.csv` contains:

| Column | Description |
|--------|-------------|
| Packet | Sequential packet number |
| Timestamp | Date and time of capture |
| Source IP | Source IP address |
| Destination IP | Destination IP address |
| Domain | DNS query domain name |
| Domain Length | Character count of domain |
| Domain Entropy | Randomness score (0-5.7) |
| Subdomain Count | Number of domain labels |
| Prediction | BENIGN ✓ or MALICIOUS ⚠️ |
| Confidence | Prediction confidence % |

## Troubleshooting

**"Permission Denied" or "tcpdump: permission denied"**
- Windows: Run PowerShell as Administrator
- Linux/macOS: Use `sudo`

**"No packets captured"**
- Make DNS requests while sniffer is running
- Check network interface: `python dns_packet_sniff.py -i eth0`
- Try different interface

**"Model file not found"**
- Ensure `model.pkl` is in the project directory
- Check filename spelling

**"Scapy not found"**
- Install: `pip install scapy`

**"No module named sklearn"**
- Install: `pip install scikit-learn`

## What is DNS Tunneling?

DNS tunneling attacks use DNS queries to exfiltrate data or communicate with command-and-control servers. They work by:
1. Encoding data into domain names
2. Using random/unnatural domain names with high entropy
3. Making frequent queries to the same malicious server

This tool detects these patterns using machine learning based on:
- High entropy in domain names
- Unusually long domains
- Many random-looking subdomains
- Density of digits and special characters
- Abnormal query patterns

## Model Information

- **Type**: Pre-trained classifier (Random Forest/Gradient Boosting)
- **Features**: 20 DNS-related features
- **Accuracy**: 94-96% on diverse DNS traffic
- **Trained on**: Benign vs. DNS tunneling traffic

## Files

- `dns_packet_sniff.py` - Main sniffer script
- `model.pkl` - Pre-trained ML model (required)
- `dns_analysis.csv` - Output results (auto-generated)
- `README.md` - This file

## Requirements

- Python 3.6+
- Scapy (`pip install scapy`)
- Scikit-learn (`pip install scikit-learn`)
- Administrator/root privileges (for packet capture)

## Notes

- Packet capture requires elevated privileges
- The model was trained on diverse DNS traffic
- Confidence scores reflect model certainty
- Results are appended to CSV file (not overwritten)

## License
Educational use in network security courses.

🔧 Active development — extending real-time pipeline and adding cross-dataset evaluation.

## Warning
- This is an academic project, all details mentioned are for learning and harmless intentions, any harmful usage of any information related to this project assigns the responsibility for the actor, and not any member of the team.

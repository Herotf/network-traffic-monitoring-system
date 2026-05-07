# 🛡️ NetWatch — Smart Network Traffic Monitor

## Quick Start

### 1. Install dependencies
```bash
pip install -r requirements.txt
```

### 2. Run the dashboard
```bash
python app.py
```
Open: http://localhost:5000

### 3. (Optional) Live packet capture with Scapy
```bash
sudo python netwatch_capture.py
```
This captures real traffic from your NIC and streams it to the dashboard.
Without it, the dashboard runs a realistic traffic simulation.

---

## Features
- 📊 Real-time bandwidth timeline chart (60-second window)
- 🔴 DDoS detection with animated alert banner
- 🌐 Per-IP session table with malicious IP flagging
- 📡 Protocol distribution (TCP/UDP/ICMP/HTTP/HTTPS)
- ⚡ Packets/sec bar chart
- 📈 Bandwidth utilization gauge
- 🔔 Live alert feed with severity levels
- 📧 Email alerts via SMTP (configure in ⚙ Settings)
- 🎛️ Configurable thresholds via UI

## Email Alerts Setup (Gmail)
1. Enable 2FA on your Google account
2. Generate an App Password: Google Account → Security → App Passwords
3. Click ⚙ in the dashboard, fill in your Gmail + App Password
4. Critical alerts (DDoS, threshold breach) trigger emails automatically

## Cisco Packet Tracer Integration
Use Packet Tracer to simulate your network topology, then:
- Export traffic logs from routers/switches
- Feed them into `netwatch_capture.py` via Scapy's `rdpcap()`

## Wireshark Integration
Capture a `.pcap` file in Wireshark, then replay it:
```python
from scapy.all import rdpcap, sniff
pkts = rdpcap("capture.pcap")
for pkt in pkts:
    process_packet(pkt)
```

"""
netwatch_capture.py
─────────────────────────────────────────────────────────
Live packet capture using Scapy (uses your real network interface).
Run this separately with: sudo python netwatch_capture.py

Requires: pip install scapy requests
Sends live data to the Flask dashboard via HTTP.
─────────────────────────────────────────────────────────
"""

import time
import threading
import requests
from collections import defaultdict
from datetime import datetime

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, get_if_list
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("⚠  Scapy not installed. Run: pip install scapy")

DASHBOARD_URL = "http://localhost:5000"
REPORT_INTERVAL = 1  # seconds

# ─── Stats ───────────────────────────────────────────────────────
stats = {
    "packets": 0,
    "bytes": 0,
    "ip_counts": defaultdict(int),
    "ip_bytes": defaultdict(int),
    "protocols": defaultdict(int),
    "start": time.time()
}
stats_lock = threading.Lock()

# ─── Packet Handler ──────────────────────────────────────────────
def process_packet(pkt):
    with stats_lock:
        stats["packets"] += 1
        if IP in pkt:
            src = pkt[IP].src
            size = len(pkt)
            stats["bytes"] += size
            stats["ip_counts"][src] += 1
            stats["ip_bytes"][src] += size

            if TCP in pkt:
                stats["protocols"]["TCP"] += 1
                dport = pkt[TCP].dport
                if dport == 80:  stats["protocols"]["HTTP"] += 1
                elif dport == 443: stats["protocols"]["HTTPS"] += 1
            elif UDP in pkt:
                stats["protocols"]["UDP"] += 1
            elif ICMP in pkt:
                stats["protocols"]["ICMP"] += 1

# ─── Reporter ────────────────────────────────────────────────────
def reporter():
    global stats
    while True:
        time.sleep(REPORT_INTERVAL)
        with stats_lock:
            elapsed = time.time() - stats["start"]
            pps = stats["packets"] / max(elapsed, 0.001)
            bps = stats["bytes"] / max(elapsed, 0.001)
            mbps = (bps * 8) / 1_000_000

            # Top IPs
            top_ips = sorted(stats["ip_counts"].items(), key=lambda x: x[1], reverse=True)[:15]
            ip_breakdown = [
                {"ip": ip, "connections": cnt, "bandwidth": round(stats["ip_bytes"][ip]*8/1_000_000/elapsed, 2),
                 "packets": cnt, "type": "external", "country": "??"}
                for ip, cnt in top_ips
            ]

            payload = {
                "timestamp": datetime.now().strftime("%H:%M:%S"),
                "bandwidth_mbps": round(mbps, 2),
                "packets_per_sec": int(pps),
                "active_connections": len(stats["ip_counts"]),
                "ddos_active": pps > 50000 or mbps > 900,
                "ip_breakdown": ip_breakdown,
                "protocol_split": dict(stats["protocols"]),
                "total_bytes": stats["bytes"],
                "dropped_packets": 0,
                "latency_ms": 0
            }

            # Reset
            stats = {
                "packets": 0, "bytes": 0,
                "ip_counts": defaultdict(int),
                "ip_bytes": defaultdict(int),
                "protocols": defaultdict(int),
                "start": time.time()
            }

        try:
            requests.post(f"{DASHBOARD_URL}/api/live_push", json=payload, timeout=1)
        except Exception as e:
            print(f"Dashboard unreachable: {e}")

        print(f"[{datetime.now().strftime('%H:%M:%S')}] {pps:.0f} pps | {mbps:.1f} Mbps | {len(top_ips)} IPs")

# ─── Main ────────────────────────────────────────────────────────
if __name__ == "__main__":
    if not SCAPY_AVAILABLE:
        print("Install scapy first: pip install scapy")
        exit(1)

    print("🛡  NetWatch Capture Engine")
    print(f"   Interfaces: {', '.join(get_if_list())}")
    print(f"   Reporting to: {DASHBOARD_URL}")
    print("   (Ctrl+C to stop)\n")

    t = threading.Thread(target=reporter, daemon=True)
    t.start()

    try:
        sniff(prn=process_packet, store=False)
    except PermissionError:
        print("❌ Run with sudo: sudo python netwatch_capture.py")
    except KeyboardInterrupt:
        print("\n✓ Capture stopped.")

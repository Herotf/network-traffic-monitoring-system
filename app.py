from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
import threading
import time
import random
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from collections import deque
from datetime import datetime
import json

app = Flask(__name__)
app.config['SECRET_KEY'] = 'netwatch-secret-2024'
socketio = SocketIO(app, cors_allowed_origins="*")

# ─── Config ───────────────────────────────────────────────────────────────────
EMAIL_CONFIG = {
    "sender": "alerts@netwatch.local",
    "recipient": "admin@company.com",
    "smtp_host": "smtp.gmail.com",
    "smtp_port": 587,
    "username": "",   # fill in
    "password": "",   # fill in
    "enabled": False
}

THRESHOLDS = {
    "bandwidth_mbps": 900,
    "packets_per_sec": 50000,
    "connections_per_ip": 500,
    "ddos_spike_ratio": 3.0
}

# ─── State ────────────────────────────────────────────────────────────────────
traffic_history = deque(maxlen=60)
alerts = deque(maxlen=100)
suspicious_ips = {}
baseline_bw = 200
alert_cooldown = {}

# ─── Helpers ──────────────────────────────────────────────────────────────────
KNOWN_MALICIOUS = ["185.220.101.", "45.33.32.", "192.42.116.", "104.21."]
COUNTRIES = ["US", "CN", "RU", "DE", "BR", "IN", "KR", "FR", "UK", "JP"]

def generate_ip():
    if random.random() < 0.04:
        base = random.choice(KNOWN_MALICIOUS)
        return base + str(random.randint(1, 254))
    return f"{random.randint(1,254)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

def classify_ip(ip):
    for mal in KNOWN_MALICIOUS:
        if ip.startswith(mal):
            return "malicious"
    first = int(ip.split(".")[0])
    if first in [10, 172, 192]:
        return "internal"
    return "external"

def send_alert_email(subject, body):
    if not EMAIL_CONFIG["enabled"] or not EMAIL_CONFIG["username"]:
        return
    try:
        msg = MIMEMultipart()
        msg['From'] = EMAIL_CONFIG["sender"]
        msg['To'] = EMAIL_CONFIG["recipient"]
        msg['Subject'] = f"🚨 NetWatch Alert: {subject}"
        msg.attach(MIMEText(body, 'html'))
        with smtplib.SMTP(EMAIL_CONFIG["smtp_host"], EMAIL_CONFIG["smtp_port"]) as s:
            s.starttls()
            s.login(EMAIL_CONFIG["username"], EMAIL_CONFIG["password"])
            s.send_message(msg)
    except Exception as e:
        print(f"Email error: {e}")

def create_alert(level, title, detail, ip=None):
    now = datetime.now().isoformat()
    key = f"{level}:{title}"
    if key in alert_cooldown and (time.time() - alert_cooldown[key]) < 30:
        return
    alert_cooldown[key] = time.time()
    alert = {"id": int(time.time()*1000), "level": level, "title": title,
              "detail": detail, "ip": ip, "time": now}
    alerts.appendleft(alert)
    socketio.emit('new_alert', alert)
    if level == "critical":
        threading.Thread(target=send_alert_email, args=(title, f"<b>{title}</b><br>{detail}<br>IP: {ip}<br>Time: {now}"), daemon=True).start()

# ─── Traffic Simulation Engine ────────────────────────────────────────────────
def simulate_traffic():
    global baseline_bw
    tick = 0
    ddos_mode = False
    ddos_ip = None
    ddos_ticks = 0

    while True:
        tick += 1
        # occasionally simulate DDoS
        if random.random() < 0.005 and not ddos_mode:
            ddos_mode = True
            ddos_ip = generate_ip()
            ddos_ticks = random.randint(8, 20)

        if ddos_mode:
            ddos_ticks -= 1
            if ddos_ticks <= 0:
                ddos_mode = False

        base = baseline_bw + random.gauss(0, 30)
        bw = base * (random.uniform(4, 8) if ddos_mode else random.uniform(0.8, 1.3))
        bw = max(0, bw)

        pps = int(bw * 140 + random.gauss(0, 500))
        active_conns = random.randint(80, 300) + (random.randint(2000, 8000) if ddos_mode else 0)

        # generate per-IP breakdown
        ip_breakdown = []
        num_ips = random.randint(8, 18)
        for _ in range(num_ips):
            ip = generate_ip()
            conns = random.randint(1, 30)
            bw_share = random.uniform(1, 40)
            ip_breakdown.append({
                "ip": ip,
                "connections": conns,
                "bandwidth": round(bw_share, 1),
                "type": classify_ip(ip),
                "country": random.choice(COUNTRIES),
                "packets": random.randint(100, 5000)
            })

        if ddos_mode and ddos_ip:
            ip_breakdown.insert(0, {
                "ip": ddos_ip,
                "connections": random.randint(800, 3000),
                "bandwidth": round(bw * 0.7, 1),
                "type": classify_ip(ddos_ip),
                "country": random.choice(COUNTRIES),
                "packets": random.randint(50000, 200000)
            })

        proto_split = {
            "TCP": random.randint(50, 70),
            "UDP": random.randint(15, 30),
            "ICMP": random.randint(1, 8),
            "HTTP": random.randint(5, 15),
            "HTTPS": random.randint(10, 25)
        }

        snapshot = {
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "bandwidth_mbps": round(bw, 2),
            "packets_per_sec": pps,
            "active_connections": active_conns,
            "ddos_active": ddos_mode,
            "ip_breakdown": ip_breakdown[:20],
            "protocol_split": proto_split,
            "total_bytes": random.randint(1_000_000, 50_000_000),
            "dropped_packets": random.randint(0, 50) + (random.randint(500, 3000) if ddos_mode else 0),
            "latency_ms": round(random.uniform(1, 8) + (random.uniform(40, 200) if ddos_mode else 0), 1)
        }
        traffic_history.append(snapshot)

        # ─── Anomaly Detection ─────────────────────────────────────────────
        if bw > THRESHOLDS["bandwidth_mbps"]:
            create_alert("critical", "Bandwidth Threshold Exceeded",
                         f"Current: {bw:.0f} Mbps (limit: {THRESHOLDS['bandwidth_mbps']} Mbps)")

        if ddos_mode:
            create_alert("critical", "DDoS Attack Detected",
                         f"Traffic spike {bw/baseline_bw:.1f}x above baseline from {ddos_ip}",
                         ip=ddos_ip)

        for ip_data in ip_breakdown:
            if ip_data["type"] == "malicious":
                create_alert("high", "Suspicious IP Detected",
                             f"Known malicious IP accessing network. {ip_data['connections']} connections",
                             ip=ip_data["ip"])
            if ip_data["connections"] > THRESHOLDS["connections_per_ip"]:
                create_alert("high", "Connection Flood",
                             f"IP exceeded connection limit: {ip_data['connections']} connections",
                             ip=ip_data["ip"])

        socketio.emit('traffic_update', snapshot)
        time.sleep(1)

# ─── Routes ───────────────────────────────────────────────────────────────────
@app.route('/')
def index():
    return render_template('dashboard.html')

@app.route('/api/history')
def history():
    return jsonify(list(traffic_history))

@app.route('/api/alerts')
def get_alerts():
    return jsonify(list(alerts))

@app.route('/api/thresholds', methods=['GET', 'POST'])
def thresholds():
    global THRESHOLDS
    if request.method == 'POST':
        data = request.json
        THRESHOLDS.update(data)
        return jsonify({"status": "ok", "thresholds": THRESHOLDS})
    return jsonify(THRESHOLDS)

@app.route('/api/email', methods=['POST'])
def set_email():
    data = request.json
    EMAIL_CONFIG.update(data)
    return jsonify({"status": "ok"})

@socketio.on('connect')
def on_connect():
    emit('history', list(traffic_history))
    emit('alerts_init', list(alerts))

if __name__ == '__main__':
    t = threading.Thread(target=simulate_traffic, daemon=True)
    t.start()
    print("\n🛡️  NetWatch running at http://localhost:5000\n")
    socketio.run(app, host='0.0.0.0', port=5000, debug=False)

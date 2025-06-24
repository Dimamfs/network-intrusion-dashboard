# network_sniffer_dashboard.py

from scapy.all import sniff, TCP, UDP, IP, DNS, DNSQR, Raw, ARP, Ether, get_working_if
from collections import defaultdict
from datetime import datetime, timedelta
from notifypy import Notify
import os
import json
import smtplib
from email.mime.text import MIMEText
from flask import Flask, render_template_string, jsonify, request
import requests
from threading import Thread

# Configuration
TIME_WINDOW = timedelta(seconds=10)
THRESHOLD = 10
LOG_FILE = "alerts.log"
BLOCKED_IPS_FILE = "blocked_ips.json"
WHITELIST = {"127.0.0.1"}
EMAIL_ALERTS = False
SMTP_SERVER = "smtp.example.com"
SMTP_PORT = 587
EMAIL_USER = "your_email@example.com"
EMAIL_PASS = "your_password"
EMAIL_TO = "recipient@example.com"
WEBHOOK_URL = "https://your-webhook-url.com"

# State
syn_counts = defaultdict(list)
dns_queries = defaultdict(int)
blocked_ips = set()
discovered_hosts = set()
traffic_counts = defaultdict(int)

if os.path.exists(BLOCKED_IPS_FILE):
    with open(BLOCKED_IPS_FILE, 'r') as file:
        blocked_ips = set(json.load(file))

def log_alert(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    full_msg = f"[{timestamp}] {message}\n"
    print(full_msg.strip())
    with open(LOG_FILE, "a", encoding="utf-8") as log:
        log.write(full_msg)
    try:
        notification = Notify()
        notification.title = "🚨 Intrusion Alert"
        notification.message = message
        notification.send()
    except Exception as e:
        print(f"Notification error: {e}")
    if EMAIL_ALERTS:
        send_email_alert(message)
        send_webhook_alert(message)

def send_email_alert(message):
    msg = MIMEText(message)
    msg['Subject'] = "Network Intrusion Alert"
    msg['From'] = EMAIL_USER
    msg['To'] = EMAIL_TO
    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        server.starttls()
        server.login(EMAIL_USER, EMAIL_PASS)
        server.send_message(msg)

def send_webhook_alert(message):
    try:
        requests.post(WEBHOOK_URL, json={"text": message}, timeout=5)
    except Exception as e:
        print(f"Webhook alert failed: {e}")

def block_ip(ip_address):
    if ip_address not in blocked_ips and ip_address not in WHITELIST:
        print(f"🔒 Blocking IP {ip_address}...")
        command = f'netsh advfirewall firewall add rule name="Block {ip_address}" dir=in action=block remoteip={ip_address}'
        os.system(command)
        blocked_ips.add(ip_address)
        with open(BLOCKED_IPS_FILE, 'w') as file:
            json.dump(list(blocked_ips), file)

def scan_network():
    print("🔍 ARP scanning...")
    from scapy.all import srp
    target_ip = "192.168.1.0/24"
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target_ip)
    result = srp(packet, timeout=2, verbose=0)[0]
    for _, received in result:
        ip = received.psrc
        if ip not in discovered_hosts:
            discovered_hosts.add(ip)
            log_alert(f"🆕 Discovered via ARP: {ip}")

def detect_packet(packet):
    now = datetime.now()
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        traffic_counts[ip_src] += 1
        if ip_src not in discovered_hosts and ip_src not in WHITELIST:
            discovered_hosts.add(ip_src)
            log_alert(f"🆕 New Device Detected: {ip_src}")
        if ip_src in WHITELIST:
            return
        if packet.haslayer(TCP) and packet[TCP].flags == 0x02:
            syn_counts[ip_src].append(now)
            syn_counts[ip_src] = [t for t in syn_counts[ip_src] if now - t < TIME_WINDOW]
            if len(syn_counts[ip_src]) > THRESHOLD:
                log_alert(f"🚨 SYN Flood from {ip_src} ({len(syn_counts[ip_src])} SYNs in 10s)")
                block_ip(ip_src)
        if packet.haslayer(DNS) and packet.haslayer(DNSQR):
            query = packet[DNSQR].qname.decode()
            dns_queries[query] += 1
            if dns_queries[query] > 20:
                log_alert(f"🔍 Suspicious DNS Query: {query} ({dns_queries[query]} times)")
        if packet.haslayer(UDP):
            log_alert(f"💬 UDP Packet from {ip_src}")
        if packet.haslayer(Raw):
            payload = str(packet[Raw].load)
            if 'HTTP' in payload:
                log_alert(f"📨 HTTP Payload from {ip_src}")

# Flask App
app = Flask(__name__)

@app.route("/")
def dashboard():
    return render_template_string(TEMPLATE)

@app.route("/logs")
def logs():
    if not os.path.exists(LOG_FILE):
        return "⚠ No alerts yet."
    with open(LOG_FILE, 'r', encoding="utf-8") as f:
        content = f.read()
        return content if content else "✅ Monitoring, no threats detected."

@app.route("/devices")
def devices():
    return jsonify(sorted(discovered_hosts))

@app.route("/traffic")
def traffic():
    return jsonify(traffic_counts)

@app.route("/block", methods=["POST"])
def block():
    ip = request.json.get("ip")
    block_ip(ip)
    return jsonify({"status": "blocked", "ip": ip})

@app.route("/unblock", methods=["POST"])
def unblock():
    ip = request.json.get("ip")
    if ip in blocked_ips:
        blocked_ips.remove(ip)
        with open(BLOCKED_IPS_FILE, 'w') as file:
            json.dump(list(blocked_ips), file)
    return jsonify({"status": "unblocked", "ip": ip})

TEMPLATE = """<!DOCTYPE html>
<html>
<head>
    <title>Network Intrusion Dashboard</title>
    <style>
        body { font-family: Arial; padding: 20px; background: #f9f9f9; }
        h1, h2 { color: #333; }
        pre, ul { background: #fff; padding: 15px; border-radius: 8px; box-shadow: 0 0 5px rgba(0,0,0,0.1); }
        .info { color: #2c3e50; }
        .syn { color: #e74c3c; }
        .dns { color: #8e44ad; }
        .http { color: #2980b9; }
        .udp { color: #f39c12; }
        .new { color: #27ae60; }
    </style>
</head>
<body>
    <h1>📡 Network Alerts</h1>
    <pre id="alerts">Loading alerts...</pre>
    <h2>🖥 Connected Devices</h2>
    <ul id="devices">Loading devices...</ul>
    <h2>📊 Traffic Stats</h2>
    <ul id="traffic">Loading traffic...</ul>
    <script>
        function classify(line) {
            if (line.includes("SYN")) return 'syn';
            if (line.includes("DNS")) return 'dns';
            if (line.includes("HTTP")) return 'http';
            if (line.includes("UDP")) return 'udp';
            if (line.includes("New Device") || line.includes("ARP")) return 'new';
            return 'info';
        }
        async function fetchLogs() {
            const res = await fetch("/logs");
            const text = await res.text();
            const lines = text.split("\\n");
            const formatted = lines.map(line => `<div class='${classify(line)}'>${line}</div>`).join('');
            document.getElementById("alerts").innerHTML = formatted;
        }
        async function fetchDevices() {
            const res = await fetch("/devices");
            const data = await res.json();
            document.getElementById("devices").innerHTML = data.map(ip => `<li>${ip} <button onclick='blockIP("${ip}")'>Block</button> <button onclick='unblockIP("${ip}")'>Unblock</button></li>`).join('');
        }
        async function fetchTraffic() {
            const res = await fetch("/traffic");
            const data = await res.json();
            document.getElementById("traffic").innerHTML = Object.entries(data).map(([ip, count]) => `<li>${ip}: ${count} packets</li>`).join('');
        }
        async function blockIP(ip) {
            await fetch("/block", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ ip }) });
            fetchDevices();
        }
        async function unblockIP(ip) {
            await fetch("/unblock", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ ip }) });
            fetchDevices();
        }
        setInterval(fetchLogs, 3000);
        setInterval(fetchDevices, 5000);
        setInterval(fetchTraffic, 5000);
        fetchLogs();
        fetchDevices();
        fetchTraffic();
    </script>
</body>
</html>
"""

if __name__ == '__main__':
    print("🛡️ Monitoring started. Run as Administrator for full access.")
    scan_network()
    log_alert("✅ Monitoring started. Test alert for dashboard display.")  # Ensure logs render
    iface = get_working_if()
    print(f"🔌 Sniffing on interface: {iface}")
    Thread(target=lambda: sniff(prn=detect_packet, store=0, iface=iface)).start()
    app.run(port=5000, debug=False)


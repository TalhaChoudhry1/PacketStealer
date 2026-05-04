from flask import Flask, jsonify, render_template_string, request
import threading
import time
import random
import json
from datetime import datetime
from collections import defaultdict

app = Flask(__name__)

# ─── State ───────────────────────────────────────────────────────────────────
monitoring = False
packets = []
packet_lock = threading.Lock()
monitor_thread = None
packet_id_counter = 0

# ─── Port → Service map ───────────────────────────────────────────────────────
PORT_SERVICES = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 80: "HTTP", 110: "POP3",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 27017: "MongoDB", 123: "NTP", 161: "SNMP",
    162: "SNMP-Trap", 500: "IKE", 514: "Syslog", 587: "SMTP-TLS",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle",
    1723: "PPTP", 5900: "VNC", 6443: "K8s-API"
}

# ─── Simulated IPs / protocols ────────────────────────────────────────────────
SOURCE_IPS = [
    "192.168.1.5", "192.168.1.12", "10.0.0.4", "172.16.0.3",
    "192.168.0.101", "10.10.5.22", "192.168.2.88", "172.20.1.9"
]
DEST_IPS = [
    "8.8.8.8", "1.1.1.1", "142.250.80.46", "151.101.1.67",
    "104.21.14.1", "13.32.100.5", "185.199.108.153", "93.184.216.34"
]
PROTOCOLS = ["TCP", "UDP", "ICMP"]
PROTOCOL_WEIGHTS = [0.6, 0.3, 0.1]
COMMON_PORTS = list(PORT_SERVICES.keys())
RANDOM_PORTS = [52000 + i * 37 % 10000 for i in range(50)]


def get_service(port):
    return PORT_SERVICES.get(port, f"PORT-{port}")


def generate_packet():
    global packet_id_counter
    packet_id_counter += 1
    proto = random.choices(PROTOCOLS, weights=PROTOCOL_WEIGHTS)[0]
    src_port = random.choice(COMMON_PORTS + RANDOM_PORTS)
    dst_port = random.choice(COMMON_PORTS)
    size = random.randint(40, 1500)
    flags = []
    if proto == "TCP":
        possible = ["SYN", "ACK", "FIN", "RST", "PSH"]
        flags = random.sample(possible, k=random.randint(1, 3))
    return {
        "id": packet_id_counter,
        "time": datetime.now().strftime("%H:%M:%S.%f")[:-3],
        "src_ip": random.choice(SOURCE_IPS),
        "dst_ip": random.choice(DEST_IPS),
        "protocol": proto,
        "src_port": src_port,
        "dst_port": dst_port,
        "size": size,
        "service": get_service(dst_port),
        "flags": flags,
        "ttl": random.randint(32, 128),
        "checksum": hex(random.randint(0x1000, 0xFFFF)),
        "payload_preview": "".join(
            random.choices("0123456789abcdef", k=random.randint(8, 32))
        ),
    }


def monitor_loop():
    global monitoring
    while monitoring:
        pkt = generate_packet()
        with packet_lock:
            packets.append(pkt)
            if len(packets) > 2000:
                packets.pop(0)
        time.sleep(random.uniform(0.08, 0.35))


# ─── Routes ──────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template_string(HTML_PAGE)


@app.route("/start", methods=["POST"])
def start():
    global monitoring, monitor_thread, packets, packet_id_counter
    if not monitoring:
        monitoring = True
        packets = []
        packet_id_counter = 0
        monitor_thread = threading.Thread(target=monitor_loop, daemon=True)
        monitor_thread.start()
    return jsonify({"status": "started"})


@app.route("/stop", methods=["POST"])
def stop():
    global monitoring
    monitoring = False
    return jsonify({"status": "stopped"})


@app.route("/packets")
def get_packets():
    proto   = request.args.get("protocol", "").upper()
    src_ip  = request.args.get("src_ip", "").strip()
    dst_ip  = request.args.get("dst_ip", "").strip()
    since   = int(request.args.get("since", 0))

    with packet_lock:
        result = [p for p in packets if p["id"] > since]

    if proto and proto != "ALL":
        result = [p for p in result if p["protocol"] == proto]
    if src_ip:
        result = [p for p in result if src_ip in p["src_ip"]]
    if dst_ip:
        result = [p for p in result if dst_ip in p["dst_ip"]]

    return jsonify({"packets": result, "monitoring": monitoring})


@app.route("/stats")
def stats():
    with packet_lock:
        data = list(packets)

    total = len(data)
    proto_count = defaultdict(int)
    total_size = 0
    service_count = defaultdict(int)

    for p in data:
        proto_count[p["protocol"]] += 1
        total_size += p["size"]
        service_count[p["service"]] += 1

    avg_size = round(total_size / total, 1) if total else 0
    top_services = sorted(service_count.items(), key=lambda x: -x[1])[:5]

    return jsonify({
        "total": total,
        "tcp": proto_count["TCP"],
        "udp": proto_count["UDP"],
        "icmp": proto_count["ICMP"],
        "avg_size": avg_size,
        "top_services": top_services,
        "monitoring": monitoring,
    })


@app.route("/packet/<int:pid>")
def get_packet(pid):
    with packet_lock:
        for p in packets:
            if p["id"] == pid:
                return jsonify(p)
    return jsonify({"error": "not found"}), 404


# ─── HTML ─────────────────────────────────────────────────────────────────────
HTML_PAGE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PacketStealer</title>
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@300;500;700&family=Orbitron:wght@400;700;900&display=swap" rel="stylesheet">
<style>
  :root {
    --bg:        #050810;
    --panel:     #080d1a;
    --border:    #0f3460;
    --accent:    #00f5d4;
    --accent2:   #f72585;
    --accent3:   #7209b7;
    --text:      #c9d6e3;
    --dim:       #4a5568;
    --tcp:       #00f5d4;
    --udp:       #ffd60a;
    --icmp:      #f72585;
    --glow:      0 0 12px #00f5d480;
    --glow2:     0 0 12px #f7258580;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }

  body {
    background: var(--bg);
    color: var(--text);
    font-family: 'Share Tech Mono', monospace;
    min-height: 100vh;
    overflow-x: hidden;
  }

  /* Scanline overlay */
  body::before {
    content: '';
    position: fixed; inset: 0; z-index: 9999;
    pointer-events: none;
    background: repeating-linear-gradient(
      0deg,
      transparent,
      transparent 2px,
      rgba(0,0,0,0.08) 2px,
      rgba(0,0,0,0.08) 4px
    );
  }

  /* Corner decoration */
  .corner { position: absolute; width: 16px; height: 16px; }
  .corner.tl { top: 0; left: 0; border-top: 2px solid var(--accent); border-left: 2px solid var(--accent); }
  .corner.tr { top: 0; right: 0; border-top: 2px solid var(--accent); border-right: 2px solid var(--accent); }
  .corner.bl { bottom: 0; left: 0; border-bottom: 2px solid var(--accent); border-left: 2px solid var(--accent); }
  .corner.br { bottom: 0; right: 0; border-bottom: 2px solid var(--accent); border-right: 2px solid var(--accent); }

  /* ── Header ── */
  header {
    display: flex; align-items: center; justify-content: space-between;
    padding: 18px 28px;
    border-bottom: 1px solid var(--border);
    background: linear-gradient(90deg, #080d1a, #050810);
    position: relative;
  }
  .logo {
    font-family: 'Orbitron', sans-serif;
    font-size: 1.7rem;
    font-weight: 900;
    letter-spacing: 4px;
    color: var(--accent);
    text-shadow: var(--glow), 0 0 40px #00f5d440;
  }
  .logo span { color: var(--accent2); text-shadow: var(--glow2); }
  .tagline {
    font-size: 0.65rem;
    color: var(--dim);
    letter-spacing: 3px;
    text-transform: uppercase;
    margin-top: 2px;
  }
  .status-bar {
    display: flex; align-items: center; gap: 20px;
    font-size: 0.7rem; color: var(--dim); letter-spacing: 1px;
  }
  .status-dot {
    width: 8px; height: 8px; border-radius: 50%;
    background: var(--dim);
    transition: all .3s;
  }
  .status-dot.active {
    background: var(--accent);
    box-shadow: 0 0 8px var(--accent), 0 0 20px var(--accent);
    animation: pulse 1.2s infinite;
  }
  @keyframes pulse {
    0%,100% { transform: scale(1); opacity: 1; }
    50%      { transform: scale(1.4); opacity: .7; }
  }
  .sys-time { color: var(--accent); font-family: 'Orbitron', sans-serif; font-size: .75rem; }

  /* ── Layout ── */
  .layout {
    display: grid;
    grid-template-columns: 260px 1fr;
    grid-template-rows: auto 1fr;
    height: calc(100vh - 70px);
    gap: 0;
  }

  /* ── Sidebar ── */
  .sidebar {
    grid-row: 1 / 3;
    border-right: 1px solid var(--border);
    padding: 20px 16px;
    display: flex; flex-direction: column; gap: 20px;
    background: var(--panel);
    overflow-y: auto;
  }

  .panel-label {
    font-size: .6rem; letter-spacing: 3px; color: var(--dim);
    text-transform: uppercase; margin-bottom: 10px;
    display: flex; align-items: center; gap: 8px;
  }
  .panel-label::after {
    content: ''; flex: 1; height: 1px; background: var(--border);
  }

  /* Controls */
  .ctrl-group { display: flex; flex-direction: column; gap: 8px; }
  .btn {
    width: 100%; padding: 11px 16px;
    font-family: 'Orbitron', sans-serif;
    font-size: .72rem; font-weight: 700; letter-spacing: 2px;
    border: 1px solid; cursor: pointer;
    text-transform: uppercase;
    transition: all .2s;
    position: relative; overflow: hidden;
    background: transparent;
  }
  .btn::before {
    content: ''; position: absolute;
    inset: 0; opacity: 0; transition: opacity .2s;
  }
  .btn:hover::before { opacity: 1; }

  .btn-start {
    color: var(--accent); border-color: var(--accent);
  }
  .btn-start::before { background: #00f5d415; }
  .btn-start:hover {
    box-shadow: var(--glow); color: #fff;
    text-shadow: var(--glow);
  }
  .btn-stop {
    color: var(--accent2); border-color: var(--accent2);
  }
  .btn-stop::before { background: #f7258515; }
  .btn-stop:hover { box-shadow: var(--glow2); }

  .btn-filter {
    color: #7209b7; border-color: #7209b7; padding: 8px 16px;
  }
  .btn-filter::before { background: #7209b715; }
  .btn-filter:hover { box-shadow: 0 0 12px #7209b7; color: var(--text); }

  .btn-clear {
    color: var(--dim); border-color: var(--dim); padding: 8px 16px; font-size: .62rem;
  }
  .btn-clear:hover { color: var(--text); border-color: var(--text); }

  /* Filter inputs */
  .filter-group { display: flex; flex-direction: column; gap: 8px; }
  .filter-group label { font-size: .6rem; color: var(--dim); letter-spacing: 2px; text-transform: uppercase; }
  .filter-group select,
  .filter-group input {
    width: 100%; background: #0a1020; border: 1px solid var(--border);
    color: var(--accent); font-family: 'Share Tech Mono', monospace; font-size: .78rem;
    padding: 7px 10px;
    outline: none; transition: border-color .2s;
    appearance: none;
  }
  .filter-group select:focus,
  .filter-group input:focus { border-color: var(--accent); box-shadow: 0 0 6px #00f5d430; }
  .filter-group input::placeholder { color: var(--dim); }

  /* Stats mini */
  .stat-mini { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; }
  .stat-box {
    background: #090f1f; border: 1px solid var(--border);
    padding: 10px 8px; text-align: center;
    position: relative; overflow: hidden;
  }
  .stat-box::before {
    content: ''; position: absolute;
    top: 0; left: 0; right: 0; height: 2px;
  }
  .stat-box.tcp::before  { background: var(--tcp); }
  .stat-box.udp::before  { background: var(--udp); }
  .stat-box.icmp::before { background: var(--icmp); }
  .stat-box.total::before { background: linear-gradient(90deg, var(--accent), var(--accent2)); }
  .stat-val {
    font-family: 'Orbitron', sans-serif; font-size: 1.3rem; font-weight: 700;
    color: var(--accent); line-height: 1;
  }
  .stat-box.udp .stat-val  { color: var(--udp); }
  .stat-box.icmp .stat-val { color: var(--icmp); }
  .stat-box.total .stat-val { color: #fff; }
  .stat-lbl { font-size: .55rem; color: var(--dim); letter-spacing: 2px; margin-top: 4px; }

  .avg-box {
    background: #090f1f; border: 1px solid var(--border); padding: 10px 12px;
    display: flex; justify-content: space-between; align-items: center;
    border-left: 3px solid var(--accent3);
  }
  .avg-lbl { font-size: .6rem; color: var(--dim); letter-spacing: 2px; }
  .avg-val { font-family: 'Orbitron', sans-serif; font-size: .9rem; color: var(--accent3); }

  /* Top services */
  .service-list { display: flex; flex-direction: column; gap: 5px; }
  .service-row {
    display: flex; justify-content: space-between; align-items: center;
    font-size: .68rem; padding: 5px 8px;
    background: #090f1f; border-left: 2px solid var(--accent3);
  }
  .service-name { color: var(--text); }
  .service-cnt { color: var(--accent3); font-family: 'Orbitron', sans-serif; font-size: .65rem; }

  /* ── Top bar (stats row) ── */
  .topbar {
    border-bottom: 1px solid var(--border);
    padding: 12px 20px;
    display: flex; gap: 20px; align-items: center;
    font-size: .65rem; color: var(--dim);
    background: var(--panel);
    flex-wrap: wrap;
  }
  .topbar-item { display: flex; align-items: center; gap: 6px; }
  .topbar-val { color: var(--accent); font-family: 'Orbitron', sans-serif; }

  /* ── Packet table ── */
  .table-wrap {
    overflow-y: auto; flex: 1;
    background: var(--bg);
  }
  .main-area {
    display: flex; flex-direction: column;
    overflow: hidden;
  }

  table { width: 100%; border-collapse: collapse; font-size: .72rem; }
  thead th {
    position: sticky; top: 0; z-index: 10;
    background: #060b16; padding: 9px 12px;
    text-align: left; font-size: .58rem;
    letter-spacing: 2px; text-transform: uppercase;
    color: var(--dim); border-bottom: 1px solid var(--border);
    font-family: 'Rajdhani', sans-serif; font-weight: 500;
    white-space: nowrap;
  }
  tbody tr {
    border-bottom: 1px solid #0d1a2d;
    cursor: pointer; transition: background .12s;
    animation: rowIn .2s ease;
  }
  @keyframes rowIn {
    from { opacity: 0; transform: translateX(-6px); }
    to   { opacity: 1; transform: none; }
  }
  tbody tr:hover { background: #0e1c34; }
  tbody tr.selected { background: #0a2040 !important; border-left: 3px solid var(--accent); }
  td { padding: 7px 12px; white-space: nowrap; color: var(--text); }
  td.id { color: var(--dim); font-size: .65rem; }
  td.src { color: #64b5f6; }
  td.dst { color: #81c784; }

  .proto-tag {
    display: inline-block; padding: 2px 8px;
    font-family: 'Orbitron', sans-serif; font-size: .58rem;
    font-weight: 700; letter-spacing: 1px;
    border: 1px solid;
  }
  .proto-tag.TCP  { color: var(--tcp);  border-color: var(--tcp);  background: #00f5d410; }
  .proto-tag.UDP  { color: var(--udp);  border-color: var(--udp);  background: #ffd60a10; }
  .proto-tag.ICMP { color: var(--icmp); border-color: var(--icmp); background: #f7258510; }

  .svc-tag {
    display: inline-block; padding: 2px 7px;
    font-size: .58rem; border: 1px solid #7209b760;
    color: #a855f7; background: #7209b710; letter-spacing: 1px;
  }

  /* ── Detail panel ── */
  .detail-panel {
    height: 220px; border-top: 1px solid var(--border);
    background: var(--panel);
    display: flex; flex-direction: column;
    transition: height .25s ease;
    flex-shrink: 0;
  }
  .detail-panel.collapsed { height: 36px; }
  .detail-header {
    padding: 8px 16px; font-size: .6rem; letter-spacing: 3px;
    color: var(--dim); text-transform: uppercase;
    display: flex; justify-content: space-between; align-items: center;
    border-bottom: 1px solid var(--border); cursor: pointer;
    user-select: none; flex-shrink: 0;
  }
  .detail-header span { color: var(--accent); }
  .detail-body { display: flex; flex: 1; overflow: hidden; }

  .detail-col {
    flex: 1; padding: 12px 16px;
    border-right: 1px solid var(--border);
    overflow-y: auto; font-size: .7rem;
  }
  .detail-col:last-child { border-right: none; }
  .detail-row {
    display: flex; gap: 10px; margin-bottom: 7px;
    border-bottom: 1px solid #0d1a2d; padding-bottom: 7px;
  }
  .detail-key { color: var(--dim); width: 110px; flex-shrink: 0; letter-spacing: 1px; font-size: .65rem; }
  .detail-val { color: var(--accent); word-break: break-all; }
  .detail-val.red { color: var(--icmp); }
  .detail-val.yellow { color: var(--udp); }

  .hex-dump {
    font-size: .62rem; color: var(--dim); letter-spacing: 1px;
    word-break: break-all; line-height: 1.8;
    padding: 8px;
    background: #060b16; border: 1px solid var(--border);
    margin-top: 4px;
  }
  .hex-dump span { color: var(--accent2); }

  /* ── Log ── */
  .log-section {
    height: 130px; border-top: 1px solid var(--border);
    background: #040710; overflow-y: auto;
    padding: 8px 14px; flex-shrink: 0;
  }
  .log-line {
    font-size: .65rem; color: var(--dim);
    padding: 2px 0; border-bottom: 1px solid #0a1020;
    display: flex; gap: 10px;
  }
  .log-line .lt { color: var(--accent3); flex-shrink: 0; }
  .log-line.alert .msg { color: var(--accent2); }
  .log-line.ok .msg { color: var(--accent); }
  .log-line.info .msg { color: var(--text); }

  /* ── Scrollbar ── */
  ::-webkit-scrollbar { width: 5px; height: 5px; }
  ::-webkit-scrollbar-track { background: var(--bg); }
  ::-webkit-scrollbar-thumb { background: var(--border); }
  ::-webkit-scrollbar-thumb:hover { background: var(--accent); }

  /* ── No data ── */
  .no-data {
    text-align: center; color: var(--dim); font-size: .8rem;
    padding: 60px 20px; letter-spacing: 2px;
  }
  .no-data .big {
    font-family: 'Orbitron', sans-serif; font-size: 2rem;
    color: #0f3460; display: block; margin-bottom: 10px;
  }

  /* ── Flag badge ── */
  .flag {
    display: inline-block; padding: 1px 5px;
    font-size: .55rem; border: 1px solid #4a5568;
    color: var(--dim); margin-right: 2px; margin-bottom: 2px;
  }
  .flag.SYN { border-color: var(--tcp); color: var(--tcp); }
  .flag.ACK { border-color: #4caf50; color: #4caf50; }
  .flag.FIN { border-color: var(--udp); color: var(--udp); }
  .flag.RST { border-color: var(--icmp); color: var(--icmp); }
  .flag.PSH { border-color: var(--accent3); color: var(--accent3); }
</style>
</head>
<body>

<header>
  <div>
    <div class="logo">PACKET<span>STEALER</span></div>
    <div class="tagline">network traffic interception &amp; analysis</div>
  </div>
  <div class="status-bar">
    <div style="display:flex;align-items:center;gap:8px;">
      <div class="status-dot" id="sdot"></div>
      <span id="sstatus">IDLE</span>
    </div>
    <div class="sys-time" id="stime"></div>
  </div>
</header>

<div class="layout">

  <!-- ── Sidebar ── -->
  <aside class="sidebar">

    <div>
      <div class="panel-label">// CONTROL</div>
      <div class="ctrl-group">
        <button class="btn btn-start" onclick="startMon()">▶ START MONITORING</button>
        <button class="btn btn-stop"  onclick="stopMon()">■ STOP MONITORING</button>
      </div>
    </div>

    <div>
      <div class="panel-label">// FILTER</div>
      <div class="filter-group">
        <label>Protocol</label>
        <select id="fProto">
          <option value="">ALL</option>
          <option>TCP</option>
          <option>UDP</option>
          <option>ICMP</option>
        </select>
        <label>Source IP</label>
        <input id="fSrc" type="text" placeholder="e.g. 192.168.1">
        <label>Destination IP</label>
        <input id="fDst" type="text" placeholder="e.g. 8.8.8.8">
      </div>
      <div style="display:flex;gap:8px;margin-top:10px;">
        <button class="btn btn-filter" onclick="applyFilter()">APPLY</button>
        <button class="btn btn-clear"  onclick="clearFilter()">CLEAR</button>
      </div>
    </div>

    <div>
      <div class="panel-label">// STATISTICS</div>
      <div class="stat-mini">
        <div class="stat-box total"><div class="stat-val" id="sTot">0</div><div class="stat-lbl">TOTAL</div></div>
        <div class="stat-box tcp"><div class="stat-val" id="sTcp">0</div><div class="stat-lbl">TCP</div></div>
        <div class="stat-box udp"><div class="stat-val" id="sUdp">0</div><div class="stat-lbl">UDP</div></div>
        <div class="stat-box icmp"><div class="stat-val" id="sIcmp">0</div><div class="stat-lbl">ICMP</div></div>
      </div>
      <div class="avg-box" style="margin-top:8px;">
        <div class="avg-lbl">AVG SIZE</div>
        <div class="avg-val" id="sAvg">— B</div>
      </div>
    </div>

    <div>
      <div class="panel-label">// TOP SERVICES</div>
      <div class="service-list" id="svcList">
        <div style="color:var(--dim);font-size:.65rem;text-align:center;padding:10px;">No data yet</div>
      </div>
    </div>

  </aside>

  <!-- ── Main area ── -->
  <div class="main-area">

    <!-- topbar -->
    <div class="topbar">
      <div class="topbar-item">CAPTURED <span class="topbar-val" id="tbTotal" style="margin-left:6px;">0</span></div>
      <div class="topbar-item">DISPLAYED <span class="topbar-val" id="tbShown" style="margin-left:6px;">0</span></div>
      <div class="topbar-item">RATE <span class="topbar-val" id="tbRate" style="margin-left:6px;">0 pkt/s</span></div>
      <div style="flex:1"></div>
      <div style="font-size:.58rem;color:var(--dim);">CLICK ROW → PACKET DETAILS</div>
    </div>

    <!-- table -->
    <div class="table-wrap" id="tableWrap">
      <div class="no-data" id="noData">
        <span class="big">◈</span>
        START MONITORING TO CAPTURE PACKETS
      </div>
      <table id="pktTable" style="display:none">
        <thead>
          <tr>
            <th>#ID</th>
            <th>TIMESTAMP</th>
            <th>SRC IP</th>
            <th>SRC PORT</th>
            <th>DST IP</th>
            <th>DST PORT</th>
            <th>PROTOCOL</th>
            <th>SERVICE</th>
            <th>SIZE</th>
          </tr>
        </thead>
        <tbody id="pktBody"></tbody>
      </table>
    </div>

    <!-- detail panel -->
    <div class="detail-panel" id="detailPanel">
      <div class="detail-header" onclick="toggleDetail()">
        <span>// PACKET DETAIL</span>
        <span id="detailTitle">— select a packet —</span>
        <span id="detailToggle">▼</span>
      </div>
      <div class="detail-body" id="detailBody">
        <div class="detail-col" id="detailLeft" style="display:flex;align-items:center;justify-content:center;color:var(--dim);font-size:.7rem;letter-spacing:2px;">
          NO PACKET SELECTED
        </div>
        <div class="detail-col" id="detailRight" style="display:none;"></div>
      </div>
    </div>

    <!-- log section -->
    <div class="log-section" id="logSection"></div>

  </div>
</div>

<script>
const MAX_ROWS = 300;
let monitoring = false;
let lastId = 0;
let allPackets = [];
let displayedRows = new Map(); // id -> tr
let selectedId = null;
let detailCollapsed = false;
let rateCount = 0;
let lastRateTime = Date.now();
let filterProto = '', filterSrc = '', filterDst = '';

// Clock
function tickClock() {
  document.getElementById('stime').textContent = new Date().toLocaleTimeString('en-GB',{hour12:false});
}
setInterval(tickClock, 1000); tickClock();

// Rate
setInterval(() => {
  const now = Date.now();
  const elapsed = (now - lastRateTime) / 1000;
  const rate = elapsed > 0 ? (rateCount / elapsed).toFixed(1) : 0;
  document.getElementById('tbRate').textContent = rate + ' pkt/s';
  rateCount = 0;
  lastRateTime = now;
}, 2000);

function log(msg, type='info') {
  const el = document.getElementById('logSection');
  const t = new Date().toLocaleTimeString('en-GB',{hour12:false});
  const div = document.createElement('div');
  div.className = 'log-line ' + type;
  div.innerHTML = `<span class="lt">[${t}]</span><span class="msg">${msg}</span>`;
  el.prepend(div);
  while (el.children.length > 80) el.lastChild.remove();
}

async function startMon() {
  await fetch('/start', {method:'POST'});
  monitoring = true;
  lastId = 0; allPackets = [];
  document.getElementById('sdot').classList.add('active');
  document.getElementById('sstatus').textContent = 'LIVE';
  document.getElementById('noData').style.display = 'none';
  document.getElementById('pktTable').style.display = '';
  document.getElementById('pktBody').innerHTML = '';
  displayedRows.clear(); allPackets = [];
  log('Monitoring started', 'ok');
  poll();
}

async function stopMon() {
  await fetch('/stop', {method:'POST'});
  monitoring = false;
  document.getElementById('sdot').classList.remove('active');
  document.getElementById('sstatus').textContent = 'STOPPED';
  log('Monitoring stopped', 'alert');
}

function applyFilter() {
  filterProto = document.getElementById('fProto').value;
  filterSrc   = document.getElementById('fSrc').value.trim();
  filterDst   = document.getElementById('fDst').value.trim();
  // Rerender
  document.getElementById('pktBody').innerHTML = '';
  displayedRows.clear();
  renderRows(allPackets);
  log(`Filter applied → proto=${filterProto||'ALL'} src=${filterSrc||'*'} dst=${filterDst||'*'}`);
}

function clearFilter() {
  filterProto = ''; filterSrc = ''; filterDst = '';
  document.getElementById('fProto').value = '';
  document.getElementById('fSrc').value = '';
  document.getElementById('fDst').value = '';
  document.getElementById('pktBody').innerHTML = '';
  displayedRows.clear();
  renderRows(allPackets);
  log('Filter cleared');
}

function matchFilter(p) {
  if (filterProto && p.protocol !== filterProto) return false;
  if (filterSrc  && !p.src_ip.includes(filterSrc)) return false;
  if (filterDst  && !p.dst_ip.includes(filterDst)) return false;
  return true;
}

function renderRows(pkts) {
  const tbody = document.getElementById('pktBody');
  const toAdd = pkts.filter(p => !displayedRows.has(p.id) && matchFilter(p));
  toAdd.forEach(p => {
    const tr = document.createElement('tr');
    tr.dataset.id = p.id;
    tr.innerHTML = `
      <td class="id">#${p.id}</td>
      <td>${p.time}</td>
      <td class="src">${p.src_ip}</td>
      <td>${p.src_port}</td>
      <td class="dst">${p.dst_ip}</td>
      <td>${p.dst_port}</td>
      <td><span class="proto-tag ${p.protocol}">${p.protocol}</span></td>
      <td><span class="svc-tag">${p.service}</span></td>
      <td>${p.size}B</td>
    `;
    tr.onclick = () => selectPacket(p.id);
    tbody.prepend(tr);
    displayedRows.set(p.id, tr);
    rateCount++;
  });
  // Trim
  const rows = tbody.querySelectorAll('tr');
  if (rows.length > MAX_ROWS) {
    for (let i = MAX_ROWS; i < rows.length; i++) {
      const id = parseInt(rows[i].dataset.id);
      displayedRows.delete(id);
      rows[i].remove();
    }
  }
  document.getElementById('tbShown').textContent = tbody.querySelectorAll('tr').length;
}

async function poll() {
  if (!monitoring) return;
  try {
    const r = await fetch(`/packets?since=${lastId}&protocol=${filterProto}&src_ip=${filterSrc}&dst_ip=${filterDst}`);
    const d = await r.json();
    if (d.packets.length) {
      d.packets.forEach(p => allPackets.push(p));
      if (allPackets.length > 2000) allPackets = allPackets.slice(-2000);
      lastId = d.packets[d.packets.length - 1].id;
      renderRows(d.packets);
      document.getElementById('tbTotal').textContent = lastId;
    }
    if (!d.monitoring) { monitoring = false; return; }
  } catch(e) { log('Poll error: ' + e, 'alert'); }
  setTimeout(poll, 400);
}

// Stats refresh
setInterval(async () => {
  try {
    const r = await fetch('/stats');
    const d = await r.json();
    document.getElementById('sTot').textContent  = d.total;
    document.getElementById('sTcp').textContent  = d.tcp;
    document.getElementById('sUdp').textContent  = d.udp;
    document.getElementById('sIcmp').textContent = d.icmp;
    document.getElementById('sAvg').textContent  = d.avg_size + ' B';
    // Services
    const svcEl = document.getElementById('svcList');
    if (d.top_services && d.top_services.length) {
      svcEl.innerHTML = d.top_services.map(([name, cnt]) =>
        `<div class="service-row"><span class="service-name">${name}</span><span class="service-cnt">${cnt}</span></div>`
      ).join('');
    }
  } catch(e) {}
}, 1500);

// Packet detail
async function selectPacket(id) {
  if (selectedId !== null) {
    const prev = displayedRows.get(selectedId);
    if (prev) prev.classList.remove('selected');
  }
  selectedId = id;
  const tr = displayedRows.get(id);
  if (tr) tr.classList.add('selected');

  try {
    const r = await fetch(`/packet/${id}`);
    const p = await r.json();
    showDetail(p);
  } catch(e) {}
}

function showDetail(p) {
  document.getElementById('detailTitle').textContent = `PKT #${p.id} | ${p.src_ip} → ${p.dst_ip}`;

  const flags = (p.flags||[]).map(f => `<span class="flag ${f}">${f}</span>`).join('');

  document.getElementById('detailLeft').innerHTML = `
    <div class="detail-row"><span class="detail-key">PACKET ID</span><span class="detail-val">#${p.id}</span></div>
    <div class="detail-row"><span class="detail-key">TIMESTAMP</span><span class="detail-val">${p.time}</span></div>
    <div class="detail-row"><span class="detail-key">SOURCE IP</span><span class="detail-val">${p.src_ip}</span></div>
    <div class="detail-row"><span class="detail-key">SRC PORT</span><span class="detail-val">${p.src_port}</span></div>
    <div class="detail-row"><span class="detail-key">DEST IP</span><span class="detail-val yellow">${p.dst_ip}</span></div>
    <div class="detail-row"><span class="detail-key">DST PORT</span><span class="detail-val yellow">${p.dst_port}</span></div>
    <div class="detail-row"><span class="detail-key">PROTOCOL</span><span class="detail-val"><span class="proto-tag ${p.protocol}">${p.protocol}</span></span></div>
    <div class="detail-row"><span class="detail-key">SERVICE</span><span class="detail-val"><span class="svc-tag">${p.service}</span></span></div>
    <div class="detail-row"><span class="detail-key">SIZE</span><span class="detail-val">${p.size} bytes</span></div>
    <div class="detail-row"><span class="detail-key">TTL</span><span class="detail-val">${p.ttl}</span></div>
    <div class="detail-row"><span class="detail-key">CHECKSUM</span><span class="detail-val red">${p.checksum}</span></div>
    ${p.flags && p.flags.length ? `<div class="detail-row"><span class="detail-key">TCP FLAGS</span><span class="detail-val">${flags}</span></div>` : ''}
  `;

  const hex = p.payload_preview || '';
  const hexSpaced = hex.match(/.{1,2}/g).map(b => `<span>${b}</span>`).join(' ');
  document.getElementById('detailRight').style.display = '';
  document.getElementById('detailRight').innerHTML = `
    <div class="panel-label" style="margin-bottom:8px;">// PAYLOAD PREVIEW</div>
    <div class="hex-dump">${hexSpaced}</div>
    <div class="panel-label" style="margin-top:14px;margin-bottom:6px;">// RAW FIELDS</div>
    <div style="font-size:.63rem;color:var(--dim);line-height:2;">
      frame.len = ${p.size}<br>
      ip.src = ${p.src_ip}<br>
      ip.dst = ${p.dst_ip}<br>
      ${p.protocol.toLowerCase()}.srcport = ${p.src_port}<br>
      ${p.protocol.toLowerCase()}.dstport = ${p.dst_port}<br>
      ip.ttl = ${p.ttl}<br>
      frame.checksum = ${p.checksum}
    </div>
  `;

  if (detailCollapsed) toggleDetail();
  log(`Inspecting #${p.id} | ${p.src_ip}:${p.src_port} → ${p.dst_ip}:${p.dst_port} [${p.protocol}]`, 'info');
}

function toggleDetail() {
  detailCollapsed = !detailCollapsed;
  document.getElementById('detailPanel').classList.toggle('collapsed', detailCollapsed);
  document.getElementById('detailToggle').textContent = detailCollapsed ? '▲' : '▼';
}
</script>
</body>
</html>
"""

if __name__ == "__main__":
    print("\n" + "="*50)
    print("  PACKETSTEALER — Network Traffic Monitor")
    print("="*50)
    print("  Open your browser → http://127.0.0.1:5000")
    print("="*50 + "\n")
    app.run(debug=False, port=5000)

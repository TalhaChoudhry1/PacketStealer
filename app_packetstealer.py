"""
PacketStealer - Network Traffic Monitoring and Analysis Platform
Backend: Python Flask
Run: python app.py  then open http://localhost:5000
"""

from flask import Flask, jsonify, request
import csv, time, threading, os
from datetime import datetime

app = Flask(__name__)

# ── Port to Service Map ──
PORT_MAP = {
    20:"FTP-Data", 21:"FTP", 22:"SSH", 23:"Telnet",
    25:"SMTP",  53:"DNS",  67:"DHCP", 80:"HTTP",
    110:"POP3", 143:"IMAP", 443:"HTTPS", 445:"SMB",
    3306:"MySQL", 3389:"RDP", 5432:"PostgreSQL",
    6379:"Redis", 8080:"HTTP-Alt", 8443:"HTTPS-Alt", 0:"N/A"
}

def get_service(port):
    try:    return PORT_MAP.get(int(port), f"Port-{port}")
    except: return "Unknown"

# ── Global State ──
monitoring  = False
all_packets = []
logs        = []
pkt_index   = 0

def load_csv():
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "traffic_data.csv")
    rows = []
    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            row["dst_service"] = get_service(row.get("dst_port", 0))
            rows.append(row)
    return rows

def worker(dataset):
    global monitoring, all_packets, logs, pkt_index
    while monitoring and pkt_index < len(dataset):
        p = dataset[pkt_index]
        all_packets.append(p)
        logs.append(
            f"[{datetime.now().strftime('%H:%M:%S')}] "
            f"#{len(all_packets):03d} | {p['protocol']:<5} | "
            f"{p['src_ip']}:{p['src_port']} → "
            f"{p['dst_ip']}:{p['dst_port']} | "
            f"{p['packet_size']}B | {p['dst_service']}"
        )
        pkt_index += 1
        time.sleep(0.6)
    if pkt_index >= len(dataset):
        logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] ── Dataset complete ──")
        monitoring = False

# ── Routes ──
@app.route("/")
def index():
    return HTML_PAGE          # serve embedded HTML (no templates folder needed)

@app.route("/start", methods=["POST"])
def start():
    global monitoring, all_packets, logs, pkt_index
    if monitoring:
        return jsonify({"status":"already_running"})
    monitoring  = True
    all_packets = []
    logs        = []
    pkt_index   = 0
    logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] ── Monitoring STARTED ──")
    threading.Thread(target=worker, args=(load_csv(),), daemon=True).start()
    return jsonify({"status":"started"})

@app.route("/stop", methods=["POST"])
def stop():
    global monitoring
    monitoring = False
    logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] ── Monitoring STOPPED ──")
    return jsonify({"status":"stopped"})

@app.route("/packets")
def packets():
    proto  = request.args.get("protocol","").upper()
    src    = request.args.get("src_ip","")
    dst    = request.args.get("dst_ip","")
    result = all_packets
    if proto: result = [p for p in result if p["protocol"].upper()==proto]
    if src:   result = [p for p in result if src in p["src_ip"]]
    if dst:   result = [p for p in result if dst in p["dst_ip"]]
    return jsonify(result)

@app.route("/stats")
def stats():
    t = len(all_packets)
    if t == 0:
        return jsonify({"total":0,"tcp":0,"udp":0,"icmp":0,"avg_size":0,"monitoring":monitoring})
    return jsonify({
        "total": t,
        "tcp":   sum(1 for p in all_packets if p["protocol"].upper()=="TCP"),
        "udp":   sum(1 for p in all_packets if p["protocol"].upper()=="UDP"),
        "icmp":  sum(1 for p in all_packets if p["protocol"].upper()=="ICMP"),
        "avg_size": sum(int(p["packet_size"]) for p in all_packets)//t,
        "monitoring": monitoring
    })

@app.route("/logs")
def get_logs():
    return jsonify(logs[-80:])

# ── Embedded HTML (no templates folder needed) ──
HTML_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>PacketStealer — Traffic Monitor</title>
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@500;600;700&display=swap" rel="stylesheet"/>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#0a0e17;--bg2:#0f1525;--bg3:#151d30;--border:#1e2d4a;
  --accent:#00d4ff;--green:#00ff9d;--warn:#ff6b35;
  --tcp:#4da6ff;--udp:#a78bfa;--icmp:#fb923c;
  --text:#c8d8f0;--dim:#5a7090;
  --mono:'Share Tech Mono',monospace;--sans:'Rajdhani',sans-serif;
}
body{background:var(--bg);color:var(--text);font-family:var(--sans);font-size:15px;min-height:100vh}
body::before{content:'';position:fixed;inset:0;
  background-image:linear-gradient(rgba(0,212,255,.03) 1px,transparent 1px),
  linear-gradient(90deg,rgba(0,212,255,.03) 1px,transparent 1px);
  background-size:40px 40px;pointer-events:none;z-index:0}
header{position:relative;z-index:10;background:var(--bg2);border-bottom:1px solid var(--border);
  padding:0 28px;display:flex;align-items:center;justify-content:space-between;height:62px}
.logo{display:flex;align-items:center;gap:12px}
.logo-hex{width:34px;height:34px;background:linear-gradient(135deg,#ff3c3c,#ff6b35);
  clip-path:polygon(50% 0%,100% 25%,100% 75%,50% 100%,0% 75%,0% 25%);
  display:flex;align-items:center;justify-content:center;font-size:14px}
.logo h1{font-size:21px;font-weight:700;letter-spacing:2px;color:#fff}
.logo h1 span{color:var(--accent)}
.pill{font-family:var(--mono);font-size:11px;padding:5px 14px;border-radius:20px;
  border:1px solid var(--dim);color:var(--dim);transition:all .3s}
.pill.on{border-color:var(--green);color:var(--green);box-shadow:0 0 12px rgba(0,255,157,.25)}
main{position:relative;z-index:1;max-width:1380px;margin:0 auto;padding:22px 22px 48px;display:grid;gap:18px}
.card{background:var(--bg2);border:1px solid var(--border);border-radius:8px;overflow:hidden}
.ch{display:flex;align-items:center;gap:10px;padding:11px 18px;background:var(--bg3);border-bottom:1px solid var(--border)}
.ch h2{font-size:11px;font-weight:600;letter-spacing:2px;text-transform:uppercase;color:var(--dim)}
.dot{width:6px;height:6px;border-radius:50%;background:var(--accent)}
.cb{padding:18px}
.row2{display:grid;grid-template-columns:1fr 1fr;gap:18px}
/* Buttons */
.btn{font-family:var(--sans);font-size:13px;font-weight:700;letter-spacing:1.5px;
  text-transform:uppercase;padding:11px 24px;border:none;border-radius:4px;cursor:pointer;transition:all .2s;width:100%}
.btn-s{background:linear-gradient(135deg,#00b4d8,#00d4ff);color:#000}
.btn-s:hover{box-shadow:0 4px 18px rgba(0,212,255,.4)}
.btn-s:disabled,.btn-x:disabled{opacity:.35;cursor:not-allowed}
.btn-x{background:transparent;border:1px solid var(--warn);color:var(--warn)}
.btn-x:hover:not(:disabled){background:rgba(255,107,53,.1)}
.btn-f{background:linear-gradient(135deg,#6366f1,#818cf8);color:#fff;width:auto;padding:9px 22px}
.btn-r{background:transparent;border:1px solid var(--border);color:var(--dim);width:auto;padding:9px 18px}
.btn-r:hover{border-color:var(--text);color:var(--text)}
/* Stats */
.sgrid{display:grid;grid-template-columns:repeat(5,1fr);gap:14px}
.scard{background:var(--bg3);border:1px solid var(--border);border-radius:6px;padding:14px;text-align:center}
.slabel{font-size:10px;letter-spacing:1.5px;text-transform:uppercase;color:var(--dim);margin-bottom:7px}
.sval{font-family:var(--mono);font-size:26px;color:#fff}
.sval.tcp{color:var(--tcp)}.sval.udp{color:var(--udp)}.sval.icmp{color:var(--icmp)}.sval.avg{color:var(--green)}
/* Filter */
.frow{display:flex;align-items:flex-end;gap:14px;flex-wrap:wrap}
.fg{display:flex;flex-direction:column;gap:5px}
.fg label{font-size:10px;letter-spacing:1.5px;text-transform:uppercase;color:var(--dim)}
.fg select,.fg input{background:var(--bg3);border:1px solid var(--border);border-radius:4px;
  color:var(--text);font-family:var(--mono);font-size:12px;padding:8px 12px;outline:none;
  transition:border-color .2s;min-width:150px}
.fg select:focus,.fg input:focus{border-color:var(--accent)}
.fg input::placeholder{color:var(--dim)}
/* Table */
.twrap{overflow-x:auto;max-height:400px;overflow-y:auto}
.twrap::-webkit-scrollbar{width:5px;height:5px}
.twrap::-webkit-scrollbar-thumb{background:var(--border);border-radius:3px}
table{width:100%;border-collapse:collapse;font-family:var(--mono);font-size:12px}
thead{position:sticky;top:0;z-index:2}
th{background:var(--bg3);border-bottom:1px solid var(--border);padding:9px 13px;
  text-align:left;font-size:10px;letter-spacing:1.5px;text-transform:uppercase;color:var(--dim);white-space:nowrap}
td{padding:8px 13px;border-bottom:1px solid rgba(30,45,74,.5);white-space:nowrap}
tr:hover td{background:rgba(0,212,255,.04)}
.badge{display:inline-block;padding:2px 9px;border-radius:3px;font-size:10px;font-weight:700;letter-spacing:1px}
.btcp{background:rgba(77,166,255,.12);color:var(--tcp);border:1px solid rgba(77,166,255,.25)}
.budp{background:rgba(167,139,250,.12);color:var(--udp);border:1px solid rgba(167,139,250,.25)}
.bicmp{background:rgba(251,146,60,.12);color:var(--icmp);border:1px solid rgba(251,146,60,.25)}
.stag{background:rgba(0,255,157,.07);color:var(--green);border:1px solid rgba(0,255,157,.18);
  padding:2px 7px;border-radius:3px;font-size:10px}
.nodata{text-align:center;color:var(--dim);padding:38px;font-size:12px;letter-spacing:1px}
#pklabel{font-family:var(--mono);font-size:11px;color:var(--dim);margin-left:auto}
/* Log */
.logbox{background:#060a12;border-radius:4px;padding:12px;height:210px;overflow-y:auto;
  font-family:var(--mono);font-size:11px;line-height:1.9}
.logbox::-webkit-scrollbar{width:4px}
.logbox::-webkit-scrollbar-thumb{background:var(--border)}
.le{color:#3a6a8b}.le.new{color:#7ab8d4}.le.sys{color:var(--green)}
@media(max-width:860px){.sgrid{grid-template-columns:repeat(3,1fr)}.row2{grid-template-columns:1fr}}
</style>
</head>
<body>
<header>
  <div class="logo">
    <div class="logo-hex">⬡</div>
    <h1>PACKET<span>STEALER</span></h1>
  </div>
  <div id="pill" class="pill">IDLE</div>
</header>
<main>
  <!-- Controls + Filter -->
  <div class="row2">
    <div class="card">
      <div class="ch"><div class="dot"></div><h2>Monitoring Controls</h2></div>
      <div class="cb" style="display:flex;gap:12px">
        <button class="btn btn-s" id="bs" onclick="startM()">▶ Start Monitoring</button>
        <button class="btn btn-x" id="bx" onclick="stopM()" disabled>■ Stop</button>
      </div>
    </div>
    <div class="card">
      <div class="ch"><div class="dot" style="background:var(--udp)"></div><h2>Filter Traffic</h2></div>
      <div class="cb">
        <div class="frow">
          <div class="fg"><label>Protocol</label>
            <select id="fp"><option value="">All</option><option>TCP</option><option>UDP</option><option>ICMP</option></select>
          </div>
          <div class="fg"><label>Source IP</label><input id="fs" placeholder="e.g. 192.168.1.5"/></div>
          <div class="fg"><label>Destination IP</label><input id="fd" placeholder="e.g. 8.8.8.8"/></div>
          <button class="btn btn-f" onclick="applyF()">Filter</button>
          <button class="btn btn-r" onclick="resetF()">Reset</button>
        </div>
      </div>
    </div>
  </div>
  <!-- Stats -->
  <div class="card">
    <div class="ch"><div class="dot" style="background:var(--green)"></div><h2>Live Statistics</h2></div>
    <div class="cb">
      <div class="sgrid">
        <div class="scard"><div class="slabel">Total Packets</div><div class="sval" id="st">0</div></div>
        <div class="scard"><div class="slabel">TCP</div><div class="sval tcp" id="stcp">0</div></div>
        <div class="scard"><div class="slabel">UDP</div><div class="sval udp" id="sudp">0</div></div>
        <div class="scard"><div class="slabel">ICMP</div><div class="sval icmp" id="sicmp">0</div></div>
        <div class="scard"><div class="slabel">Avg Size (B)</div><div class="sval avg" id="savg">0</div></div>
      </div>
    </div>
  </div>
  <!-- Table -->
  <div class="card">
    <div class="ch"><div class="dot" style="background:var(--tcp)"></div><h2>Captured Packets</h2><span id="pklabel">0 packets</span></div>
    <div style="padding:0">
      <div class="twrap">
        <table>
          <thead><tr><th>#</th><th>Time</th><th>Source IP</th><th>Src Port</th><th>Destination IP</th><th>Dst Port</th><th>Protocol</th><th>Service</th><th>Size (B)</th></tr></thead>
          <tbody id="tbody"><tr><td colspan="9" class="nodata">Press START to begin monitoring…</td></tr></tbody>
        </table>
      </div>
    </div>
  </div>
  <!-- Log -->
  <div class="card">
    <div class="ch"><div class="dot" style="background:var(--icmp)"></div><h2>Activity Log</h2></div>
    <div class="cb" style="padding:12px 18px">
      <div class="logbox" id="logbox"><div class="le sys">[ PacketStealer v1.0 — Ready ]</div></div>
    </div>
  </div>
</main>
<script>
let timer=null, filters={protocol:'',src_ip:'',dst_ip:''};

async function startM(){
  await fetch('/start',{method:'POST'});
  document.getElementById('bs').disabled=true;
  document.getElementById('bx').disabled=false;
  const p=document.getElementById('pill');
  p.textContent='MONITORING';p.classList.add('on');
  timer=setInterval(poll,1000);
}
async function stopM(){
  await fetch('/stop',{method:'POST'});
  clearInterval(timer);
  document.getElementById('bs').disabled=false;
  document.getElementById('bx').disabled=true;
  const p=document.getElementById('pill');
  p.textContent='STOPPED';p.classList.remove('on');
  poll();
}
function applyF(){
  filters={protocol:document.getElementById('fp').value,
           src_ip:document.getElementById('fs').value.trim(),
           dst_ip:document.getElementById('fd').value.trim()};
  fetchPkts();
}
function resetF(){
  document.getElementById('fp').value='';
  document.getElementById('fs').value='';
  document.getElementById('fd').value='';
  filters={protocol:'',src_ip:'',dst_ip:''};fetchPkts();
}
async function poll(){fetchPkts();fetchStats();fetchLogs();}

async function fetchPkts(){
  const q=new URLSearchParams();
  if(filters.protocol)q.set('protocol',filters.protocol);
  if(filters.src_ip)q.set('src_ip',filters.src_ip);
  if(filters.dst_ip)q.set('dst_ip',filters.dst_ip);
  const r=await fetch('/packets?'+q);const d=await r.json();renderTable(d);
}
function renderTable(pkts){
  document.getElementById('pklabel').textContent=pkts.length+' packet'+(pkts.length!==1?'s':'');
  const tb=document.getElementById('tbody');
  if(!pkts.length){tb.innerHTML='<tr><td colspan="9" class="nodata">No packets match the filter…</td></tr>';return;}
  tb.innerHTML=pkts.map((p,i)=>`<tr>
    <td style="color:var(--dim)">${String(i+1).padStart(3,'0')}</td>
    <td>${p.time}</td><td>${p.src_ip}</td>
    <td style="color:var(--dim)">${p.src_port}</td>
    <td>${p.dst_ip}</td><td style="color:var(--dim)">${p.dst_port}</td>
    <td><span class="badge b${p.protocol.toLowerCase()}">${p.protocol}</span></td>
    <td><span class="stag">${p.dst_service}</span></td>
    <td>${p.packet_size}</td></tr>`).join('');
  const w=document.querySelector('.twrap');w.scrollTop=w.scrollHeight;
}
async function fetchStats(){
  const r=await fetch('/stats');const d=await r.json();
  document.getElementById('st').textContent=d.total;
  document.getElementById('stcp').textContent=d.tcp;
  document.getElementById('sudp').textContent=d.udp;
  document.getElementById('sicmp').textContent=d.icmp;
  document.getElementById('savg').textContent=d.avg_size;
  if(!d.monitoring&&timer){
    clearInterval(timer);timer=null;
    document.getElementById('bs').disabled=false;
    document.getElementById('bx').disabled=true;
    const p=document.getElementById('pill');
    p.textContent='COMPLETE';p.classList.remove('on');
  }
}
async function fetchLogs(){
  const r=await fetch('/logs');const logs=await r.json();
  const box=document.getElementById('logbox');
  box.innerHTML=logs.map((l,i)=>`<div class="le${i===logs.length-1?' new':''} ${l.includes('START')||l.includes('STOP')||l.includes('complete')?' sys':''}">${l}</div>`).join('');
  box.scrollTop=box.scrollHeight;
}
</script>
</body>
</html>"""

if __name__ == "__main__":
    print("\n  PacketStealer is running!")
    print("  Open your browser and go to:  http://localhost:5000\n")
    app.run(debug=False, port=5000)

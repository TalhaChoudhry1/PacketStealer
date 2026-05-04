# PacketStealer 🕵️

A web-based network traffic monitoring and analysis platform built with Python (Flask) and plain HTML/CSS/JavaScript. PacketStealer reads a structured dataset of network packets and simulates live capture — displaying packet details, protocol breakdowns, port-to-service mappings, and real-time statistics through a clean browser interface.

Built as a university project for the Computer Networks course at PUCIT.

---

## What It Does

- Simulates live packet capture by feeding a CSV dataset one packet at a time
- Shows Source IP, Destination IP, Protocol, Ports, Packet Size, and Timestamp for every packet
- Automatically maps port numbers to service names (Port 80 → HTTP, Port 443 → HTTPS, Port 53 → DNS, etc.)
- Displays live statistics — total packet count, TCP/UDP/ICMP breakdown, average packet size
- Lets you filter traffic by Protocol, Source IP, or Destination IP
- Keeps a scrollable timestamped activity log of every captured packet
- Start and Stop controls to manage the monitoring session

---

## Project Structure

```
PacketStealer/
├── app.py               # Flask backend — all logic, REST API, HTML embedded
├── traffic_data.csv     # Dataset — 50 network traffic records
└── README.md
```

> The HTML interface is embedded directly inside `app.py` so there is no separate templates folder needed. Just two files and you're done.

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3, Flask |
| Frontend | HTML5, CSS3, Vanilla JavaScript |
| Data | CSV file (traffic_data.csv) |
| Fonts | Google Fonts — Share Tech Mono, Rajdhani |

---

## Dataset

File: `traffic_data.csv` — 50 records of simulated network traffic

| Field | Example |
|---|---|
| time | 10:35:21 |
| src_ip | 192.168.1.5 |
| dst_ip | 8.8.8.8 |
| protocol | TCP |
| packet_size | 512 |
| src_port | 52341 |
| dst_port | 80 |

The dataset includes TCP (browsing, HTTPS, SSH), UDP (DNS queries), and ICMP (ping) traffic across private and public IP ranges.

---

## How to Run

**Requirements:** Python 3 and Flask

```bash
pip install flask
python app.py
```

Then open your browser and go to:

```
http://localhost:5000
```

That's it. No database setup, no config files, no extra dependencies.

---

## How to Use

1. Click **Start Monitoring** — packets start appearing in the table every 0.6 seconds
2. Watch the **Statistics** panel update as packets come in
3. Use the **Filter** panel to narrow by Protocol, Source IP, or Destination IP
4. Click **Reset** to go back to the full view
5. Click **Stop** at any time to pause monitoring
6. Check the **Activity Log** at the bottom for a full record of all captured packets

---

## Port-to-Service Mapping

| Port | Service | Port | Service |
|---|---|---|---|
| 21 | FTP | 443 | HTTPS |
| 22 | SSH | 3306 | MySQL |
| 25 | SMTP | 3389 | RDP |
| 53 | DNS | 5432 | PostgreSQL |
| 80 | HTTP | 8080 | HTTP-Alt |

---

## Possible Extensions

- Real-time packet sniffing using Python's `scapy` library (instead of CSV)
- Export captured packets to CSV or PDF
- Persistent logging to SQLite database
- Geographic IP location lookup
- Packet rate graph over time

---

## Author

**Talha Choudhry**
Roll No: BCSF24A008
4th Semester — BS Computer Science
PUCIT, University of the Punjab, Lahore

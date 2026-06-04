# 🍯 Honeypot System v3.0

![Python](https://img.shields.io/badge/Python-3.11-blue)
![Platform](https://img.shields.io/badge/Platform-Linux-green)
![License](https://img.shields.io/badge/License-MIT-red)

A multi-service honeypot system that simulates fake SSH, FTP, and HTTP servers to detect, log, and analyze attacker behavior in real time.

---

## Demo

### Terminal Output

```
[2026-05-31 02:28:24] [SSH] COMMAND  | IP: 45.33.32.156  (Moscow, Russia)     | whoami
[2026-05-31 02:28:27] [SSH] COMMAND  | IP: 45.33.32.156  (Moscow, Russia)     | ls
[2026-05-31 02:21:59] [HTTP] LOGIN   | IP: 91.108.4.1    (Beijing, China)     | admin / admin123
[2026-05-31 02:06:49] [FTP] LOGIN    | IP: 185.220.101.1 (Frankfurt, Germany) | root / toor
```

### Live Web Dashboard

Real-time attack map showing SSH, FTP, HTTP attempts with charts and geo-location tracking.

---

## Features

### Level 1 — Core
- Fake SSH server (port 2222) — captures credentials silently
- Fake FTP server (port 2121) — captures usernames and passwords
- Fake HTTP admin panel (port 8080) — captures form login attempts
- Unified CSV export of all attack logs
- Color-coded terminal output per service
- Auto port cleanup on every restart

### Level 2 — Intelligence
- Geo-IP lookup — shows attacker country and city in real time
- Live attack counter per service
- Brute force alert — triggers after 3 attempts from same IP
- Fake success dashboard — keeps attacker engaged after login

### Level 3 — Advanced
- SSH command logger — logs every command attacker types inside fake shell
- Tarpit mode — slows down brute force attackers automatically
- Email alerts — get notified when attacks are detected
- Live web dashboard — real-time browser-based attack map with charts

---

## Tech Stack

| Tool | Purpose |
|------|---------|
| Python 3.11 | Core language |
| Paramiko | Fake SSH server |
| Flask + SocketIO | Live web dashboard |
| Colorama | Terminal colors |
| Requests | Geo-IP API |
| Socket | FTP and HTTP servers |

---

## Project Structure

```
Honeypot-System/
├── launch.py            # Master launcher — runs all 3 honeypots
├── templates/
│   └── dashboard.html   # Live web dashboard
├── honeypot_logs.csv    # All attack logs (auto-generated, gitignored)
└── README.md            # Project documentation
```

---

## Installation

```bash
git clone https://github.com/saisrujan1906-beep/Honeypot-System.git
cd Honeypot-System
pip install paramiko flask flask-socketio colorama requests
python3 launch.py
```

---

## Usage

```bash
python3 launch.py
```

Then open:
- `http://localhost:5000` — Live attack dashboard
- `http://localhost:8080` — Fake admin panel for testing

**Test SSH:**
```bash
ssh -p 2222 -o StrictHostKeyChecking=no root@localhost
```

**Test FTP:**
```bash
ftp localhost 2121
```

**Test HTTP:**

Open browser and go to `http://localhost:8080` — type any credentials and hit Login.

---

## Sample CSV Log

```
Timestamp,Service,IP,Username,Password,Event,Location
2026-05-31 02:28:24,SSH,45.33.32.156,root,admin,LOGIN ATTEMPT,Moscow Russia
2026-05-31 02:28:27,SSH,45.33.32.156,root,,COMMAND,Moscow Russia
2026-05-31 02:21:59,HTTP,91.108.4.1,admin,admin123,LOGIN ATTEMPT,Beijing China
2026-05-31 02:06:49,FTP,185.220.101.1,root,toor,LOGIN ATTEMPT,Frankfurt Germany
```

---

## How It Works

```
Attacker connects
      ↓
Honeypot accepts connection
      ↓
Credentials captured silently
      ↓
Geo-IP lookup (country + city)
      ↓
Logged to CSV + Terminal + Web Dashboard
      ↓
Brute force alert if 3+ attempts from same IP
      ↓
Tarpit slows attacker down (up to 30 seconds)
      ↓
Email alert sent (if configured)
```

---

## Configuration

To enable email alerts, open `launch.py` and update:

```python
EMAIL_ALERTS = True
EMAIL_FROM   = "your@gmail.com"
EMAIL_TO     = "your@gmail.com"
EMAIL_PASS   = "your_app_password"
```

To change ports, update these at the top of `launch.py`:

```python
SSH_PORT  = 2222
FTP_PORT  = 2121
HTTP_PORT = 8080
WEB_PORT  = 5000
```

---

## Ethical Notice

This tool is built for **educational and defensive security research** only.
Deploy only on systems you own or have explicit written permission to monitor.
Unauthorized use against systems you do not own is illegal.

---

## Author

**Sai Srujan Reddy Muchantula**
B.Tech Computer Science — KLH University, Hyderabad
GitHub: [@saisrujan1906-beep](https://github.com/saisrujan1906-beep)

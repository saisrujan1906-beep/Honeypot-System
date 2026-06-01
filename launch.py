import threading
import socket
import paramiko
import datetime
import csv
import os
import time
import smtplib
import requests
from email.mime.text import MIMEText
from colorama import Fore, Style, init
from flask import Flask, render_template
from flask_socketio import SocketIO

init(autoreset=True)

# ─────────────────────────────────────────
#  CONFIG — Email alerts (optional)
# ─────────────────────────────────────────

EMAIL_ALERTS  = False       # Set True to enable
EMAIL_FROM    = "your@gmail.com"
EMAIL_TO      = "your@gmail.com"
EMAIL_PASS    = "your_app_password"

# ─────────────────────────────────────────
#  FLASK WEB DASHBOARD
# ─────────────────────────────────────────

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

@app.route("/")
def dashboard():
    return render_template("dashboard.html")

# ─────────────────────────────────────────
#  SHARED STATE
# ─────────────────────────────────────────

CSV_FILE      = "honeypot_logs.csv"
attack_counts = {"SSH": 0, "FTP": 0, "HTTP": 0}
ip_attempts   = {}
counts_lock   = threading.Lock()

# ─────────────────────────────────────────
#  EMAIL ALERT
# ─────────────────────────────────────────

def send_email(ip, service, username, password, geo):
    if not EMAIL_ALERTS:
        return
    try:
        msg = MIMEText(
            f"Honeypot Alert!\n\nService : {service}\nIP      : {ip}\nLocation: {geo}\nUsername: {username}\nPassword: {password}\nTime    : {datetime.datetime.now()}"
        )
        msg["Subject"] = f"[Honeypot] Attack detected on {service}!"
        msg["From"]    = EMAIL_FROM
        msg["To"]      = EMAIL_TO
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as s:
            s.login(EMAIL_FROM, EMAIL_PASS)
            s.send_message(msg)
    except Exception as e:
        print(Fore.RED + f"  [!] Email error: {e}" + Style.RESET_ALL)

# ─────────────────────────────────────────
#  GEO-IP LOOKUP
# ─────────────────────────────────────────

def get_geo(ip):
    try:
        if ip in ("127.0.0.1", "localhost"):
            return "Localhost"
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=3)
        data = r.json()
        if data.get("status") == "success":
            return f"{data.get('city','?')}, {data.get('country','?')}"
    except:
        pass
    return "Unknown"

# ─────────────────────────────────────────
#  ALERT SYSTEM
# ─────────────────────────────────────────

def check_alert(ip, service):
    with counts_lock:
        key = f"{ip}_{service}"
        ip_attempts[key] = ip_attempts.get(key, 0) + 1
        count = ip_attempts[key]

    if count >= 3 and count % 3 == 0:
        print(Fore.RED + Style.BRIGHT + f"""
  ╔══════════════════════════════════════════╗
  ║   BRUTE FORCE ALERT DETECTED!           ║
  ║   IP      : {ip:<30}║
  ║   Service : {service:<30}║
  ║   Attempts: {count:<30}║
  ╚══════════════════════════════════════════╝
""" + Style.RESET_ALL)
        socketio.emit("new_event", {
            "alert": True, "ip": ip,
            "service": service, "attempts": count
        })

# ─────────────────────────────────────────
#  TARPIT — slow down brute force
# ─────────────────────────────────────────

def tarpit(ip, service):
    with counts_lock:
        key   = f"{ip}_{service}"
        count = ip_attempts.get(key, 0)
    if count > 3:
        delay = min(count * 2, 30)
        print(Fore.YELLOW + f"  [~] Tarpit: slowing {ip} by {delay}s" + Style.RESET_ALL)
        time.sleep(delay)

# ─────────────────────────────────────────
#  SHARED LOG
# ─────────────────────────────────────────

def init_csv():
    if not os.path.exists(CSV_FILE):
        with open(CSV_FILE, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Timestamp","Service","IP","Username","Password","Event","Location"])

def log(service, event, ip="", username="", password="", geo=""):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    colors    = {"SSH": Fore.CYAN, "FTP": Fore.YELLOW, "HTTP": Fore.MAGENTA}
    color     = colors.get(service, Fore.WHITE)

    if "LOGIN ATTEMPT" in event:
        with counts_lock:
            attack_counts[service] += 1
        total = sum(attack_counts.values())

        print(Fore.RED   + f"  [!] LOGIN ATTEMPT" + Style.RESET_ALL)
        print(color      + f"  [{timestamp}] [{service}]" + Style.RESET_ALL)
        print(f"       IP       : {ip}  ({geo})")
        print(f"       Username : {username}")
        print(f"       Password : {password}")
        print(Fore.WHITE + f"       Totals   : SSH={attack_counts['SSH']} FTP={attack_counts['FTP']} HTTP={attack_counts['HTTP']} | All={total}\n" + Style.RESET_ALL)

        send_email(ip, service, username, password, geo)

    elif "NEW CONNECTION" in event:
        print(color + f"  [{timestamp}] [{service}] NEW CONNECTION | IP: {ip}  ({geo})" + Style.RESET_ALL)

    elif "COMMAND" in event:
        print(Fore.GREEN + f"  [{timestamp}] [{service}] COMMAND | IP: {ip} | {username}" + Style.RESET_ALL)

    else:
        print(color + f"  [{timestamp}] [{service}] {event}" + Style.RESET_ALL)

    with open(CSV_FILE, "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([timestamp, service, ip, username, password, event, geo])

    socketio.emit("new_event", {
        "timestamp": timestamp, "service": service,
        "ip": ip, "username": username,
        "password": password, "event": event,
        "geo": geo, "alert": False
    })

# ─────────────────────────────────────────
#  SSH HONEYPOT + COMMAND LOGGER
# ─────────────────────────────────────────

HOST_KEY = paramiko.RSAKey.generate(2048)

class FakeSSHServer(paramiko.ServerInterface):
    def __init__(self, client_ip, geo):
        self.client_ip = client_ip
        self.geo       = geo
        self.event     = threading.Event()

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        tarpit(self.client_ip, "SSH")
        log("SSH", "LOGIN ATTEMPT", self.client_ip, username, password, self.geo)
        check_alert(self.client_ip, "SSH")
        # Let attacker in after logging — command logger takes over
        return paramiko.AUTH_SUCCESSFUL

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def get_allowed_auths(self, username):
        return "password"

def handle_ssh_commands(channel, client_ip, geo):
    channel.send(b"\r\nWelcome to Ubuntu 22.04 LTS\r\n$ ")
    command_buffer = b""
    while True:
        try:
            data = channel.recv(1024)
            if not data:
                break
            command_buffer += data
            channel.send(data)
            if b"\r" in command_buffer or b"\n" in command_buffer:
                cmd = command_buffer.strip().decode(errors="ignore")
                if cmd:
                    log("SSH", "COMMAND", client_ip, cmd, "", geo)
                    # Fake responses
                    if cmd == "whoami":
                        channel.send(b"\r\nroot\r\n$ ")
                    elif cmd == "ls":
                        channel.send(b"\r\npasswords.txt  secrets.zip  backup.tar.gz\r\n$ ")
                    elif cmd == "pwd":
                        channel.send(b"\r\n/root\r\n$ ")
                    elif cmd in ("exit", "quit"):
                        channel.send(b"\r\nlogout\r\n")
                        break
                    else:
                        channel.send(f"\r\nbash: {cmd}: command not found\r\n$ ".encode())
                command_buffer = b""
        except:
            break

def handle_ssh(client_socket, client_ip):
    geo = get_geo(client_ip)
    log("SSH", "NEW CONNECTION", client_ip, geo=geo)
    try:
        transport = paramiko.Transport(client_socket)
        transport.add_server_key(HOST_KEY)
        server = FakeSSHServer(client_ip, geo)
        transport.start_server(server=server)
        channel = transport.accept(20)
        if channel:
            server.event.wait(10)
            handle_ssh_commands(channel, client_ip, geo)
            channel.close()
    except Exception as e:
        log("SSH", f"ERROR: {str(e)}", client_ip)
    finally:
        client_socket.close()

def start_ssh(port=2222):
    log("SSH", f"SSH Honeypot started on port {port}")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    s.listen(100)
    while True:
        client, addr = s.accept()
        threading.Thread(target=handle_ssh, args=(client, addr[0]), daemon=True).start()

# ─────────────────────────────────────────
#  FTP HONEYPOT
# ─────────────────────────────────────────

def handle_ftp(client_socket, client_ip):
    geo = get_geo(client_ip)
    log("FTP", "NEW CONNECTION", client_ip, geo=geo)
    try:
        client_socket.send(b"220 Microsoft FTP Service\r\n")
        username = None
        while True:
            data = client_socket.recv(1024).decode(errors="ignore").strip()
            if not data:
                break
            if data.upper().startswith("USER"):
                username = data[5:].strip()
                client_socket.send(b"331 Password required\r\n")
            elif data.upper().startswith("PASS"):
                password = data[5:].strip()
                tarpit(client_ip, "FTP")
                log("FTP", "LOGIN ATTEMPT", client_ip, username, password, geo)
                check_alert(client_ip, "FTP")
                client_socket.send(b"530 Login incorrect\r\n")
            elif data.upper().startswith("QUIT"):
                client_socket.send(b"221 Goodbye\r\n")
                break
            else:
                client_socket.send(b"530 Please login with USER and PASS\r\n")
    except Exception as e:
        log("FTP", f"ERROR: {str(e)}", client_ip)
    finally:
        client_socket.close()

def start_ftp(port=2121):
    log("FTP", f"FTP Honeypot started on port {port}")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    s.listen(100)
    while True:
        client, addr = s.accept()
        threading.Thread(target=handle_ftp, args=(client, addr[0]), daemon=True).start()

# ─────────────────────────────────────────
#  HTTP HONEYPOT
# ─────────────────────────────────────────

LOGIN_PAGE = """HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n
<!DOCTYPE html><html><head><title>Admin Panel</title>
<style>
body{background:#1a1a2e;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;font-family:Arial;}
.box{background:#16213e;padding:40px;border-radius:10px;width:320px;}
h2{color:#e94560;text-align:center;margin-bottom:30px;}
input{width:100%;padding:12px;margin:8px 0;background:#0f3460;border:none;border-radius:5px;color:white;box-sizing:border-box;}
button{width:100%;padding:12px;background:#e94560;border:none;border-radius:5px;color:white;font-size:16px;cursor:pointer;margin-top:10px;}
p{color:#888;text-align:center;font-size:12px;margin-top:20px;}
</style></head><body>
<div class="box"><h2>Admin Panel</h2>
<form method="POST">
<input type="text" name="username" placeholder="Username" required/>
<input type="password" name="password" placeholder="Password" required/>
<button type="submit">Login</button>
</form><p>Unauthorized access is prohibited</p>
</div></body></html>"""

FAKE_SUCCESS = """HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n
<!DOCTYPE html><html><head><title>Dashboard</title>
<style>
body{background:#1a1a2e;color:white;font-family:Arial;padding:40px;}
h1{color:#e94560;}
.card{background:#16213e;padding:20px;border-radius:10px;margin:10px 0;width:300px;}
.label{color:#888;font-size:12px;}
.value{font-size:18px;margin-top:5px;}
</style></head><body>
<h1>Welcome, Administrator</h1>
<p style="color:#888;">System Dashboard — Internal Use Only</p>
<div class="card"><div class="label">Server Status</div><div class="value" style="color:#00ff88;">Online</div></div>
<div class="card"><div class="label">Active Users</div><div class="value">1,247</div></div>
<div class="card"><div class="label">Last Backup</div><div class="value">Today, 03:00 AM</div></div>
<div class="card"><div class="label">Storage Used</div><div class="value">2.4 TB / 10 TB</div></div>
</body></html>"""

def parse_credentials(request):
    try:
        if "username=" in request and "password=" in request:
            body = request.split("\r\n\r\n", 1)[-1]
            params = {}
            for part in body.split("&"):
                if "=" in part:
                    k, v = part.split("=", 1)
                    params[k] = v.replace("+", " ")
            return params.get("username", ""), params.get("password", "")
    except:
        pass
    return None, None

def handle_http(client_socket, client_ip):
    geo = get_geo(client_ip)
    log("HTTP", "NEW CONNECTION", client_ip, geo=geo)
    try:
        request = client_socket.recv(4096).decode(errors="ignore")
        if not request:
            return
        if request.startswith("POST"):
            username, password = parse_credentials(request)
            if username and password:
                tarpit(client_ip, "HTTP")
                log("HTTP", "LOGIN ATTEMPT", client_ip, username, password, geo)
                check_alert(client_ip, "HTTP")
            client_socket.send(FAKE_SUCCESS.encode())
        else:
            client_socket.send(LOGIN_PAGE.encode())
    except Exception as e:
        log("HTTP", f"ERROR: {str(e)}", client_ip)
    finally:
        client_socket.close()

def start_http(port=8080):
    log("HTTP", f"HTTP Honeypot started on port {port}")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    s.listen(100)
    while True:
        client, addr = s.accept()
        threading.Thread(target=handle_http, args=(client, addr[0]), daemon=True).start()

# ─────────────────────────────────────────
#  MASTER LAUNCHER
# ─────────────────────────────────────────

if __name__ == "__main__":
    init_csv()

    print(Fore.GREEN + """
    ██╗  ██╗ ██████╗ ███╗   ██╗███████╗██╗   ██╗██████╗  ██████╗ ████████╗
    ██║  ██║██╔═══██╗████╗  ██║██╔════╝╚██╗ ██╔╝██╔══██╗██╔═══██╗╚══██╔══╝
    ███████║██║   ██║██╔██╗ ██║█████╗   ╚████╔╝ ██████╔╝██║   ██║   ██║   
    ██╔══██║██║   ██║██║╚██╗██║██╔══╝    ╚██╔╝  ██╔═══╝ ██║   ██║   ██║   
    ██║  ██║╚██████╔╝██║ ╚████║███████╗   ██║   ██║     ╚██████╔╝   ██║   
    ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝      ╚═════╝    ╚═╝   
    """ + Style.RESET_ALL)

    print(Fore.CYAN   + "  [*] Honeypot System v3.0 — All Levels Active" + Style.RESET_ALL)
    print(Fore.CYAN   + "  [*] SSH  → port 2222  (with command logger)" + Style.RESET_ALL)
    print(Fore.CYAN   + "  [*] FTP  → port 2121" + Style.RESET_ALL)
    print(Fore.CYAN   + "  [*] HTTP → port 8080  (with fake dashboard)" + Style.RESET_ALL)
    print(Fore.CYAN   + "  [*] Web  → port 5000  (live attack dashboard)" + Style.RESET_ALL)
    print(Fore.CYAN   + "  [*] Geo-IP, Tarpit, Alerts → enabled" + Style.RESET_ALL)
    print(Fore.YELLOW + "  [*] Open browser → http://localhost:5000\n" + Style.RESET_ALL)

    threading.Thread(target=start_ssh,  daemon=True).start()
    threading.Thread(target=start_ftp,  daemon=True).start()
    threading.Thread(target=start_http, daemon=True).start()

    # Flask runs on main thread
    socketio.run(app, host="0.0.0.0", port=5000, use_reloader=False, log_output=False)


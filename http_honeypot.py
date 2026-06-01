import socket
import threading
import datetime

LOG_FILE = "http_honeypot.log"

def log(message):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = f"[{timestamp}] {message}"
    print(entry)
    with open(LOG_FILE, "a") as f:
        f.write(entry + "\n")

def log_separator():
    with open(LOG_FILE, "a") as f:
        f.write("\n" + "="*60 + "\n")

LOGIN_PAGE = """HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n
<!DOCTYPE html>
<html>
<head>
    <title>Admin Panel</title>
    <style>
        body { background: #1a1a2e; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; font-family: Arial; }
        .box { background: #16213e; padding: 40px; border-radius: 10px; width: 320px; box-shadow: 0 0 20px rgba(0,0,0,0.5); }
        h2 { color: #e94560; text-align: center; margin-bottom: 30px; }
        input { width: 100%; padding: 12px; margin: 8px 0; background: #0f3460; border: none; border-radius: 5px; color: white; box-sizing: border-box; }
        button { width: 100%; padding: 12px; background: #e94560; border: none; border-radius: 5px; color: white; font-size: 16px; cursor: pointer; margin-top: 10px; }
        button:hover { background: #c73652; }
        p { color: #888; text-align: center; font-size: 12px; margin-top: 20px; }
    </style>
</head>
<body>
    <div class="box">
        <h2>Admin Panel</h2>
        <form method="POST">
            <input type="text" name="username" placeholder="Username" required/>
            <input type="password" name="password" placeholder="Password" required/>
            <button type="submit">Login</button>
        </form>
        <p>Unauthorized access is prohibited</p>
    </div>
</body>
</html>"""

WRONG_PAGE = """HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n
<!DOCTYPE html>
<html>
<head>
    <title>Admin Panel</title>
    <style>
        body { background: #1a1a2e; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; font-family: Arial; }
        .box { background: #16213e; padding: 40px; border-radius: 10px; width: 320px; box-shadow: 0 0 20px rgba(0,0,0,0.5); }
        h2 { color: #e94560; text-align: center; margin-bottom: 30px; }
        .error { color: #e94560; text-align: center; margin-bottom: 15px; font-size: 14px; }
        input { width: 100%; padding: 12px; margin: 8px 0; background: #0f3460; border: none; border-radius: 5px; color: white; box-sizing: border-box; }
        button { width: 100%; padding: 12px; background: #e94560; border: none; border-radius: 5px; color: white; font-size: 16px; cursor: pointer; margin-top: 10px; }
        button:hover { background: #c73652; }
        p { color: #888; text-align: center; font-size: 12px; margin-top: 20px; }
    </style>
</head>
<body>
    <div class="box">
        <h2>Admin Panel</h2>
        <div class="error">Invalid credentials. Try again.</div>
        <form method="POST">
            <input type="text" name="username" placeholder="Username" required/>
            <input type="password" name="password" placeholder="Password" required/>
            <button type="submit">Login</button>
        </form>
        <p>Unauthorized access is prohibited</p>
    </div>
</body>
</html>"""

def parse_credentials(request):
    try:
        if "username=" in request and "password=" in request:
            body = request.split("\r\n\r\n", 1)[-1]
            params = {}
            for part in body.split("&"):
                if "=" in part:
                    k, v = part.split("=", 1)
                    params[k] = v.replace("+", " ")
            username = params.get("username", "")
            password = params.get("password", "")
            return username, password
    except:
        pass
    return None, None

def handle_connection(client_socket, client_ip):
    log(f"NEW CONNECTION | IP: {client_ip}")
    try:
        request = client_socket.recv(4096).decode(errors="ignore")
        if not request:
            return

        if request.startswith("POST"):
            username, password = parse_credentials(request)
            if username and password:
                log(f"LOGIN ATTEMPT | IP: {client_ip} | Username: {username} | Password: {password}")
            client_socket.send(WRONG_PAGE.encode())

        else:
            client_socket.send(LOGIN_PAGE.encode())

    except Exception as e:
        log(f"ERROR | IP: {client_ip} | {str(e)}")
    finally:
        client_socket.close()

def start_honeypot(host="0.0.0.0", port=8080):
    log_separator()
    log(f"HTTP Honeypot started on port {port}")
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, port))
    server_socket.listen(5)

    while True:
        client_socket, client_addr = server_socket.accept()
        client_ip = client_addr[0]
        thread = threading.Thread(
            target=handle_connection,
            args=(client_socket, client_ip)
        )
        thread.daemon = True
        thread.start()

if __name__ == "__main__":
    start_honeypot()

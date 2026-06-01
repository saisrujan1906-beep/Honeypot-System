import socket
import threading
import paramiko
import datetime

# --- RSA key for our fake SSH server ---
HOST_KEY = paramiko.RSAKey.generate(2048)

LOG_FILE = "ssh_honeypot.log"

def log(message):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = f"[{timestamp}] {message}"
    print(entry)
    with open(LOG_FILE, "a") as f:
        f.write(entry + "\n")

def log_separator():
    with open(LOG_FILE, "a") as f:
        f.write("\n" + "="*60 + "\n")

class FakeSSHServer(paramiko.ServerInterface):
    def __init__(self, client_ip):
        self.client_ip = client_ip

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        log(f"LOGIN ATTEMPT | IP: {self.client_ip} | Username: {username} | Password: {password}")
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password"

def handle_connection(client_socket, client_ip):
    log(f"NEW CONNECTION | IP: {client_ip}")
    try:
        transport = paramiko.Transport(client_socket)
        transport.add_server_key(HOST_KEY)
        server = FakeSSHServer(client_ip)
        transport.start_server(server=server)
        channel = transport.accept(20)
        if channel:
            channel.close()
    except Exception as e:
        log(f"ERROR | IP: {client_ip} | {str(e)}")
    finally:
        client_socket.close()

def start_honeypot(host="0.0.0.0", port=2222):
    log_separator()
    log(f"SSH Honeypot started on port 2222")
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

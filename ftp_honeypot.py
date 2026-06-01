import socket
import threading
import datetime

LOG_FILE = "ftp_honeypot.log"

def log(message):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = f"[{timestamp}] {message}"
    print(entry)
    with open(LOG_FILE, "a") as f:
        f.write(entry + "\n")

def log_separator():
    with open(LOG_FILE, "a") as f:
        f.write("\n" + "="*60 + "\n")

def handle_connection(client_socket, client_ip):
    log(f"NEW CONNECTION | IP: {client_ip}")
    try:
        # Send fake FTP banner — looks like a real FTP server
        client_socket.send(b"220 Microsoft FTP Service\r\n")

        username = None

        while True:
            data = client_socket.recv(1024).decode(errors="ignore").strip()
            if not data:
                break

            # Attacker sends username
            if data.upper().startswith("USER"):
                username = data[5:].strip()
                log(f"USERNAME | IP: {client_ip} | Username: {username}")
                client_socket.send(b"331 Password required\r\n")

            # Attacker sends password
            elif data.upper().startswith("PASS"):
                password = data[5:].strip()
                log(f"LOGIN ATTEMPT | IP: {client_ip} | Username: {username} | Password: {password}")
                # Always reject
                client_socket.send(b"530 Login incorrect\r\n")

            # Attacker tries to quit
            elif data.upper().startswith("QUIT"):
                client_socket.send(b"221 Goodbye\r\n")
                break

            else:
                client_socket.send(b"530 Please login with USER and PASS\r\n")

    except Exception as e:
        log(f"ERROR | IP: {client_ip} | {str(e)}")
    finally:
        client_socket.close()
        log(f"CONNECTION CLOSED | IP: {client_ip}")

def start_honeypot(host="0.0.0.0", port=2121):
    log_separator()
    log(f"FTP Honeypot started on port {port}")
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

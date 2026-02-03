#!/usr/bin/env python3
"""TCP HTTP Server - Simple HTTP server with status endpoint"""
import socket
import threading
import sys
import logging
import logging.handlers
from datetime import datetime
from itertools import count
from pathlib import Path

LOG_DIR = Path('/var/log/origin')
LOG_DIR.mkdir(parents=True, exist_ok=True)

_handlers = [logging.StreamHandler()]
_file_handler = logging.handlers.RotatingFileHandler(
    LOG_DIR / 'tcp-http.log', maxBytes=5 * 1024 * 1024, backupCount=3
)
_handlers.append(_file_handler)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - TCP-HTTP - %(message)s',
    handlers=_handlers
)

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
REQUEST_COUNT = 0
CONNECTION_COUNTER = count(1)

def handle_client(conn, addr):
    global REQUEST_COUNT
    conn_id = next(CONNECTION_COUNTER)
    conn.settimeout(30)
    logging.info(f"Conn#{conn_id} accepted from {addr[0]}:{addr[1]}")
    try:
        with conn:
            data = conn.recv(4096)
            if not data:
                logging.info(f"Conn#{conn_id} closed without data")
                return

            request = data.decode('utf-8', errors='ignore')
            REQUEST_COUNT += 1

            # Parse request line
            lines = request.split('\r\n')
            if lines:
                logging.info(f"Conn#{conn_id} request line: {lines[0]}")
            logging.info(f"Conn#{conn_id} raw size={len(data)} bytes")

            # Generate response
            timestamp = datetime.now().isoformat()
            body = f"""{{
  "status": "ok",
  "service": "Origin HTTP Server",
  "timestamp": "{timestamp}",
  "client_ip": "{addr[0]}",
  "client_port": {addr[1]},
  "request_count": {REQUEST_COUNT}
}}"""

            response = f"""HTTP/1.1 200 OK\r
Content-Type: application/json\r
Content-Length: {len(body)}\r
Connection: close\r
Server: Origin-HTTP-Server/1.0\r
\r
{body}"""

            encoded = response.encode('utf-8')
            conn.sendall(encoded)
            logging.info(
                f"Conn#{conn_id} sent {len(encoded)} bytes to {addr[0]}:{addr[1]}"
            )
    except Exception as e:
        logging.error(f"Conn#{conn_id} error with {addr[0]}:{addr[1]}: {e}")
    finally:
        logging.info(f"Conn#{conn_id} closed for {addr[0]}:{addr[1]}")

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('0.0.0.0', PORT))
    server.listen(5)
    logging.info(f"TCP HTTP Server listening on port {PORT}")

    try:
        while True:
            conn, addr = server.accept()
            thread = threading.Thread(target=handle_client, args=(conn, addr))
            thread.daemon = True
            thread.start()
    except KeyboardInterrupt:
        logging.info("Server shutting down")
    finally:
        server.close()

if __name__ == '__main__':
    main()

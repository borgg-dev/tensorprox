#!/usr/bin/env python3
"""TCP Echo Server - Echoes back all received data"""
import socket
import threading
import sys
import logging
import logging.handlers
from itertools import count
from pathlib import Path
from datetime import datetime

LOG_DIR = Path('/var/log/origin')
LOG_DIR.mkdir(parents=True, exist_ok=True)

_handlers = [logging.StreamHandler()]
_file_handler = logging.handlers.RotatingFileHandler(
    LOG_DIR / 'tcp-echo.log', maxBytes=5 * 1024 * 1024, backupCount=3
)
_handlers.append(_file_handler)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - TCP-ECHO - %(message)s',
    handlers=_handlers
)

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 9001
CONNECTION_COUNTER = count(1)

def handle_client(conn, addr):
    conn_id = next(CONNECTION_COUNTER)
    conn.settimeout(30)
    logging.info(f"Conn#{conn_id} accepted from {addr[0]}:{addr[1]}")
    try:
        with conn:
            while True:
                data = conn.recv(4096)
                if not data:
                    break
                preview = data[:64]
                logging.info(
                    f"Conn#{conn_id} recv {len(data)} bytes from {addr[0]}:{addr[1]} preview={preview!r}"
                )
                conn.sendall(data)
                logging.info(
                    f"Conn#{conn_id} sent {len(data)} bytes back to {addr[0]}:{addr[1]}"
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
    logging.info(f"TCP Echo Server listening on port {PORT}")

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

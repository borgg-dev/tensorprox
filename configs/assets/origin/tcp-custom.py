#!/usr/bin/env python3
"""TCP Custom Protocol Server - Request/Response protocol with commands"""
import socket
import threading
import sys
import logging
import logging.handlers
import json
from datetime import datetime
from itertools import count
from pathlib import Path

LOG_DIR = Path('/var/log/origin')
LOG_DIR.mkdir(parents=True, exist_ok=True)

_handlers = [logging.StreamHandler()]
_file_handler = logging.handlers.RotatingFileHandler(
    LOG_DIR / 'tcp-custom.log', maxBytes=5 * 1024 * 1024, backupCount=3
)
_handlers.append(_file_handler)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - TCP-CUSTOM - %(message)s',
    handlers=_handlers
)

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 9003
SESSION_COUNTER = count(1)

def handle_client(conn, addr):
    session_id = next(SESSION_COUNTER)
    conn.settimeout(60)
    logging.info(f"Session {session_id} started from {addr[0]}:{addr[1]}")

    try:
        with conn:
            # Send welcome message
            welcome = {
                "status": "connected",
                "session_id": session_id,
                "server": "Origin Custom Protocol Server",
                "timestamp": datetime.now().isoformat(),
                "commands": ["PING", "TIME", "INFO", "QUIT"]
            }
            conn.sendall((json.dumps(welcome) + "\n").encode('utf-8'))

            while True:
                data = conn.recv(4096)
                if not data:
                    break

                command = data.decode('utf-8').strip().upper()
                logging.info(
                    f"Session {session_id}: received {len(data)} bytes command='{command}'"
                )

                response = {}
                if command == "PING":
                    response = {"status": "pong", "session_id": session_id}
                elif command == "TIME":
                    response = {"status": "ok", "time": datetime.now().isoformat()}
                elif command == "INFO":
                    response = {
                        "status": "ok",
                        "server": "Origin Custom Server",
                        "version": "1.0",
                        "session_id": session_id,
                        "client": f"{addr[0]}:{addr[1]}"
                    }
                elif command == "QUIT":
                    response = {"status": "goodbye", "session_id": session_id}
                    conn.sendall((json.dumps(response) + "\n").encode('utf-8'))
                    break
                else:
                    response = {"status": "error", "message": f"Unknown command: {command}"}

                conn.sendall((json.dumps(response) + "\n").encode('utf-8'))
                logging.info(f"Session {session_id}: sent response")

    except Exception as e:
        logging.error(f"Session {session_id} error: {e}")
    finally:
        logging.info(f"Session {session_id} ended")

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('0.0.0.0', PORT))
    server.listen(5)
    logging.info(f"TCP Custom Protocol Server listening on port {PORT}")

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

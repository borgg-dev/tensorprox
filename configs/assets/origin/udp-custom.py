#!/usr/bin/env python3
"""UDP Custom Protocol Server - Command-based UDP protocol"""
import socket
import sys
import logging
import json
from datetime import datetime

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - UDP-CUSTOM - %(message)s'
)

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 9103
REQUEST_COUNT = 0

def main():
    global REQUEST_COUNT
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('0.0.0.0', PORT))
    logging.info(f"UDP Custom Protocol Server listening on port {PORT}")

    try:
        while True:
            data, addr = sock.recvfrom(4096)
            REQUEST_COUNT += 1

            try:
                command = data.decode('utf-8').strip().upper()
                logging.info(f"Request #{REQUEST_COUNT} from {addr[0]}:{addr[1]}: '{command}'")

                response = {}
                if command == "PING":
                    response = {"status": "pong", "request_id": REQUEST_COUNT}
                elif command == "TIME":
                    response = {"status": "ok", "time": datetime.now().isoformat()}
                elif command == "STATUS":
                    response = {
                        "status": "ok",
                        "server": "Origin UDP Custom Server",
                        "version": "1.0",
                        "uptime": "N/A",
                        "requests_served": REQUEST_COUNT
                    }
                elif command == "HELLO":
                    response = {
                        "status": "hello",
                        "message": f"Hello from Origin Server!",
                        "client": f"{addr[0]}:{addr[1]}"
                    }
                else:
                    response = {"status": "error", "message": f"Unknown command: {command}"}

                response_data = json.dumps(response).encode('utf-8')
                sock.sendto(response_data, addr)
                logging.info(f"Sent response to {addr[0]}:{addr[1]}")

            except Exception as e:
                logging.error(f"Error processing request: {e}")
                error_response = json.dumps({"status": "error", "message": str(e)}).encode('utf-8')
                sock.sendto(error_response, addr)

    except KeyboardInterrupt:
        logging.info("Server shutting down")
    finally:
        sock.close()

if __name__ == '__main__':
    main()

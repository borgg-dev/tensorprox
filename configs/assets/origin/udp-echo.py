#!/usr/bin/env python3
"""UDP Echo Server - Echoes back all received datagrams"""
import socket
import sys
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - UDP-ECHO - %(message)s'
)

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 9101

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('0.0.0.0', PORT))
    logging.info(f"UDP Echo Server listening on port {PORT}")

    try:
        while True:
            data, addr = sock.recvfrom(4096)
            logging.info(f"Received {len(data)} bytes from {addr[0]}:{addr[1]}")
            sock.sendto(data, addr)
            logging.info(f"Echoed {len(data)} bytes back to {addr[0]}:{addr[1]}")
    except KeyboardInterrupt:
        logging.info("Server shutting down")
    finally:
        sock.close()

if __name__ == '__main__':
    main()

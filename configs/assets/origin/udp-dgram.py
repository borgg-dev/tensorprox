#!/usr/bin/env python3
"""UDP Datagram Server - Logs datagrams and sends acknowledgments"""
import socket
import sys
import logging
from datetime import datetime

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - UDP-DGRAM - %(message)s'
)

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 9102
PACKET_COUNT = 0

def main():
    global PACKET_COUNT
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('0.0.0.0', PORT))
    logging.info(f"UDP Datagram Server listening on port {PORT}")

    try:
        while True:
            data, addr = sock.recvfrom(4096)
            PACKET_COUNT += 1
            timestamp = datetime.now().isoformat()

            logging.info(f"Packet #{PACKET_COUNT} from {addr[0]}:{addr[1]} - {len(data)} bytes")

            # Send acknowledgment
            ack = f"ACK:{PACKET_COUNT}:{timestamp}:{len(data)}".encode('utf-8')
            sock.sendto(ack, addr)
            logging.info(f"Sent ACK to {addr[0]}:{addr[1]}")
    except KeyboardInterrupt:
        logging.info("Server shutting down")
    finally:
        sock.close()

if __name__ == '__main__':
    main()

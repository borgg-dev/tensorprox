"""
Direct TUN Device Packet Injector.

Writes raw packets directly to WireGuard TUN device, bypassing kernel
IP validation. This allows sending:
- Malformed packets (ihl < 5) - kernel would reject with EINVAL
- Fragmented packets - kernel may reassemble/drop before WireGuard
- Any arbitrary byte sequence

Security: Packets still go through authenticated WireGuard tunnel.

The Linux kernel validates outgoing packets at the IP layer BEFORE
WireGuard encrypts them. By writing directly to the TUN device file
descriptor (or using AF_PACKET SOCK_RAW), we bypass this validation.
"""

import os
import struct
import fcntl
from typing import List, Optional, Tuple
from dataclasses import dataclass

from loguru import logger


# TUN device constants
TUNSETIFF = 0x400454ca
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000  # Don't include packet info header


@dataclass
class TunInjector:
    """
    Direct TUN device writer for arbitrary packet injection.

    Writes raw IP packets to TUN device, bypassing kernel validation.
    Used for sending malformed/fragmented packets through WireGuard tunnel.

    Usage:
        injector = TunInjector("wga58_57")
        if injector.open():
            # Send malformed packet (ihl=2, which is invalid)
            malformed = build_malformed_packet("10.100.57.1", ihl=2)
            injector.write_packet(malformed)
            injector.close()
    """
    interface_name: str
    _tun_fd: Optional[int] = None
    _sock: any = None
    _using_fallback: bool = False

    def open(self) -> bool:
        """
        Open TUN interface for writing.

        Tries direct TUN fd first, falls back to AF_PACKET SOCK_RAW.
        """
        # Try AF_PACKET SOCK_RAW first - more reliable for existing WG interfaces
        if self._try_af_packet():
            return True

        # Fallback to direct TUN fd (may fail if WG has the fd)
        return self._try_tun_fd()

    def _try_af_packet(self) -> bool:
        """Use AF_PACKET SOCK_RAW for packet injection."""
        try:
            import socket

            # SOCK_RAW on AF_PACKET bypasses more kernel checks than SOCK_DGRAM
            ETH_P_IP = 0x0800
            self._sock = socket.socket(
                socket.AF_PACKET,
                socket.SOCK_RAW,
                socket.htons(ETH_P_IP)
            )
            self._sock.bind((self.interface_name, 0))
            self._using_fallback = True

            logger.debug(f"TunInjector: Using AF_PACKET SOCK_RAW for {self.interface_name}")
            return True

        except PermissionError:
            logger.debug(f"AF_PACKET requires CAP_NET_RAW")
            return False
        except OSError as e:
            logger.debug(f"AF_PACKET failed: {e}")
            return False

    def _try_tun_fd(self) -> bool:
        """Try to open TUN device fd directly."""
        try:
            # Open clone device
            self._tun_fd = os.open("/dev/net/tun", os.O_RDWR)

            # Attach to existing interface
            # Pack: 16 bytes name + 2 bytes flags + 14 bytes padding
            ifr = struct.pack('16sH14s',
                              self.interface_name.encode()[:16],
                              IFF_TUN | IFF_NO_PI,
                              b'\x00' * 14)

            fcntl.ioctl(self._tun_fd, TUNSETIFF, ifr)

            logger.debug(f"TunInjector: Opened TUN fd for {self.interface_name}")
            return True

        except PermissionError:
            logger.debug("TUN requires CAP_NET_ADMIN or root")
            if self._tun_fd is not None:
                os.close(self._tun_fd)
                self._tun_fd = None
            return False
        except OSError as e:
            if e.errno == 16:  # EBUSY - device in use
                logger.debug(f"TUN device busy (WireGuard using it)")
            else:
                logger.debug(f"TUN open failed: {e}")
            if self._tun_fd is not None:
                os.close(self._tun_fd)
                self._tun_fd = None
            return False

    def write_packet(self, raw_bytes: bytes) -> bool:
        """
        Write raw IP packet bytes to the TUN device.

        No validation is performed - bytes are written as-is.
        WireGuard will encrypt and send them.

        Args:
            raw_bytes: Complete IP packet (header + data)

        Returns:
            True if write succeeded
        """
        if self._using_fallback and self._sock is not None:
            return self._write_af_packet(raw_bytes)

        if self._tun_fd is not None:
            try:
                written = os.write(self._tun_fd, raw_bytes)
                return written == len(raw_bytes)
            except OSError as e:
                logger.debug(f"TUN write failed: {e}")
                return False

        return False

    def _write_af_packet(self, raw_bytes: bytes) -> bool:
        """Write via AF_PACKET socket."""
        try:
            # For SOCK_RAW on TUN, we need to build a minimal eth header
            # But for TUN interfaces, WireGuard expects raw IP
            self._sock.send(raw_bytes)
            return True
        except OSError as e:
            # Log first few failures for debugging
            if not hasattr(self, '_error_count'):
                self._error_count = 0
            self._error_count += 1
            if self._error_count <= 5:
                ihl = raw_bytes[0] & 0x0F if raw_bytes else 0
                frag = int.from_bytes(raw_bytes[6:8], 'big') if len(raw_bytes) >= 8 else 0
                logger.debug(f"AF_PACKET write failed: {e} (ihl={ihl}, frag=0x{frag:04x})")
            return False

    def write_packets(self, packets: List[bytes]) -> Tuple[int, int]:
        """
        Write multiple packets.

        Returns:
            Tuple of (success_count, error_count)
        """
        success = 0
        errors = 0
        for pkt in packets:
            if self.write_packet(pkt):
                success += 1
            else:
                errors += 1
        return success, errors

    def close(self):
        """Close the TUN device."""
        if self._tun_fd is not None:
            os.close(self._tun_fd)
            self._tun_fd = None
        if self._sock is not None:
            self._sock.close()
            self._sock = None


def build_malformed_packet(dest_ip: str, src_ip: str = "10.100.57.2", ihl: int = 2) -> bytes:
    """
    Build a malformed IP packet with invalid IHL.

    Args:
        dest_ip: Destination IP address
        src_ip: Source IP address (tunnel IP)
        ihl: IP Header Length field (valid is >= 5, we use < 5)

    Returns:
        Raw packet bytes
    """
    # IP header with invalid IHL
    version_ihl = (4 << 4) | (ihl & 0x0F)  # Version=4, IHL=invalid
    tos = 0
    total_len = 40  # Minimum IP + TCP
    ident = 0x1234
    flags_frag = 0  # No fragmentation
    ttl = 64
    proto = 6  # TCP
    checksum = 0  # Will be wrong, but XDP catches malformed before checksum

    src_bytes = bytes([int(x) for x in src_ip.split('.')])
    dst_bytes = bytes([int(x) for x in dest_ip.split('.')])

    header = struct.pack('!BBHHHBBH4s4s',
        version_ihl, tos, total_len, ident, flags_frag,
        ttl, proto, checksum, src_bytes, dst_bytes
    )

    # Add minimal TCP header
    tcp_header = bytes([
        0x12, 0x34,  # Source port (4660)
        0x00, 0x50,  # Dest port (80)
        0x00, 0x00, 0x00, 0x01,  # Seq
        0x00, 0x00, 0x00, 0x00,  # Ack
        0x50, 0x02,  # Data offset + SYN flag
        0x72, 0x10,  # Window
        0x00, 0x00,  # Checksum
        0x00, 0x00,  # Urgent ptr
    ])

    return header + tcp_header


def build_tiny_fragment(dest_ip: str, src_ip: str = "1.2.3.4") -> bytes:
    """
    Build a tiny first fragment (MF flag set, < 68 bytes).

    Args:
        dest_ip: Destination IP
        src_ip: Source IP (can be spoofed)

    Returns:
        Raw packet bytes (36 bytes total: IP 20 + UDP 8 + 8 payload)
    """
    version_ihl = (4 << 4) | 5  # Valid IHL=5
    tos = 0
    total_len = 36  # IP(20) + UDP(8) + 8 payload = 36 < 68
    ident = 0x5678
    # MF flag set, offset = 0 (first fragment)
    flags_frag = 0x2000  # More Fragments
    ttl = 64
    proto = 17  # UDP
    checksum = 0

    src_bytes = bytes([int(x) for x in src_ip.split('.')])
    dst_bytes = bytes([int(x) for x in dest_ip.split('.')])

    ip_header = struct.pack('!BBHHHBBH4s4s',
        version_ihl, tos, total_len, ident, flags_frag,
        ttl, proto, checksum, src_bytes, dst_bytes
    )

    # UDP header (8 bytes)
    udp_header = struct.pack('!HHHH',
        4660,   # Source port
        80,     # Dest port
        16,     # Length (8 header + 8 payload)
        0       # Checksum (0 = disabled)
    )

    # Minimal payload
    payload = b'TINYFRAG'

    return ip_header + udp_header + payload


def build_overlapping_fragment(dest_ip: str, src_ip: str = "1.2.3.4", offset: int = 10) -> bytes:
    """
    Build an overlapping fragment (non-zero offset, no MF).

    This simulates a middle/last fragment of a larger packet.

    Args:
        dest_ip: Destination IP
        src_ip: Source IP (can be spoofed)
        offset: Fragment offset in 8-byte units

    Returns:
        Raw packet bytes
    """
    version_ihl = (4 << 4) | 5  # Valid IHL=5
    tos = 0
    total_len = 48  # IP(20) + 28 payload
    ident = 0x9ABC
    # No MF, non-zero offset (simulates last fragment)
    flags_frag = offset & 0x1FFF
    ttl = 64
    proto = 17  # UDP
    checksum = 0

    src_bytes = bytes([int(x) for x in src_ip.split('.')])
    dst_bytes = bytes([int(x) for x in dest_ip.split('.')])

    ip_header = struct.pack('!BBHHHBBH4s4s',
        version_ihl, tos, total_len, ident, flags_frag,
        ttl, proto, checksum, src_bytes, dst_bytes
    )

    # Payload (this would be the data portion of the fragment)
    payload = b'OVERLAP_FRAGMENT_DATA____'[:28]

    return ip_header + payload

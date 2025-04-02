#!/usr/bin/env python3
"""
BPF Loader for TensorProx DDoS Protection

This module handles loading and attaching the XDP BPF program to network interfaces,
as well as setting up and managing BPF maps for DDoS protection.
"""

import os
import time
import subprocess
import ctypes
import json
from typing import Dict, List, Optional, Tuple, Union
import struct
from loguru import logger

# Try to import pyroute2 and bcc, but provide fallbacks if not available
try:
    from pyroute2 import IPRoute
    from pyroute2.netlink.exceptions import NetlinkError
    HAVE_PYROUTE2 = True
except ImportError:
    HAVE_PYROUTE2 = False
    logger.warning("pyroute2 not installed, falling back to subprocess for XDP operations")

try:
    import bcc
    HAVE_BCC = True
except ImportError:
    HAVE_BCC = False
    logger.warning("BCC not installed, falling back to libbpf-based tools")

# Data structures for BPF maps
class FlowKey(ctypes.Structure):
    _fields_ = [
        ("src_ip", ctypes.c_uint32),
        ("dst_ip", ctypes.c_uint32),
        ("src_port", ctypes.c_uint16),
        ("dst_port", ctypes.c_uint16),
        ("protocol", ctypes.c_uint8),
    ]

class FlowVerdict(ctypes.Structure):
    _fields_ = [
        ("action", ctypes.c_uint8),
        ("priority", ctypes.c_uint8),
        ("timestamp", ctypes.c_uint32),
        ("packet_count", ctypes.c_uint32),
        ("byte_count", ctypes.c_uint32),
        ("rate_limit", ctypes.c_uint32),
    ]

class SamplingConfig(ctypes.Structure):
    _fields_ = [
        ("base_rate", ctypes.c_uint32),
        ("syn_rate", ctypes.c_uint32),
        ("udp_rate", ctypes.c_uint32),
        ("icmp_rate", ctypes.c_uint32),
        ("min_size", ctypes.c_uint32),
        ("max_size", ctypes.c_uint32),
        ("size_rate", ctypes.c_uint32),
    ]

class IfaceMap(ctypes.Structure):
    _fields_ = [
        ("ingress_ifindex", ctypes.c_uint32),
        ("egress_ifindex", ctypes.c_uint32),
        ("enabled", ctypes.c_uint8),
    ]

class Metrics(ctypes.Structure):
    _fields_ = [
        ("total_packets", ctypes.c_uint64),
        ("allowed_packets", ctypes.c_uint64),
        ("blocked_packets", ctypes.c_uint64),
        ("sampled_packets", ctypes.c_uint64),
        ("syn_packets", ctypes.c_uint64),
        ("udp_packets", ctypes.c_uint64),
        ("icmp_packets", ctypes.c_uint64),
        ("other_packets", ctypes.c_uint64),
    ]

# Constants for verdict actions
VERDICT_UNKNOWN = 0
VERDICT_ALLOW = 1
VERDICT_BLOCK = 2
VERDICT_RATE_LIMIT = 3

class BPFLoader:
    """Manages loading and updating XDP programs and their maps for DDoS protection."""

    def __init__(self, xdp_path: str = None, artifacts_dir: str = None, use_generic: bool = False):
        """
        Initialize the BPF loader.

        Args:
            xdp_path: Path to the XDP program file (default: built-in location)
            artifacts_dir: Directory for BPF compilation artifacts
            use_generic: Use generic XDP mode even if native is supported
        """
        self.xdp_path = xdp_path or os.path.join(
            os.path.dirname(os.path.abspath(__file__)), 
            "moat_xdp_core.c"
        )
        self.artifacts_dir = artifacts_dir or "/tmp/tensorprox_xdp"
        self.use_generic = use_generic
        self.bpf = None
        self.attached_interfaces = {}  # Track attached interfaces
        self.interface_indexes = {}    # Map interface names to indexes
        self.initialized = False
        
        # Create artifacts directory if it doesn't exist
        if not os.path.exists(self.artifacts_dir):
            os.makedirs(self.artifacts_dir)
    
    def detect_interface_indexes(self) -> Dict[str, int]:
        """Get interface indexes for all network interfaces."""
        ifaces = {}
        
        if HAVE_PYROUTE2:
            with IPRoute() as ip:
                links = ip.get_links()
                for link in links:
                    attrs = dict(link.get('attrs', []))
                    if 'IFLA_IFNAME' in attrs:
                        ifaces[attrs['IFLA_IFNAME']] = link.get('index', 0)
        else:
            # Fallback to parsing ip link command
            try:
                output = subprocess.check_output(['ip', '-o', 'link'], text=True)
                for line in output.split('\n'):
                    if not line.strip():
                        continue
                    parts = line.split(':', 2)
                    if len(parts) >= 2:
                        idx = parts[0].strip()
                        name = parts[1].strip()
                        if idx.isdigit() and name:
                            ifaces[name] = int(idx)
            except subprocess.SubprocessError as e:
                logger.error(f"Failed to get interface indexes: {e}")
        
        self.interface_indexes = ifaces
        return ifaces
    
    def get_interface_index(self, interface: str) -> int:
        """Get the index of a network interface."""
        if not self.interface_indexes:
            self.detect_interface_indexes()
        
        return self.interface_indexes.get(interface, 0)
    
    def compile_xdp(self) -> str:
        """
        Compile the XDP program.
        
        Returns:
            Path to the compiled object file
        """
        object_file = os.path.join(self.artifacts_dir, "moat_xdp_core.o")
        
        # Compile using clang
        try:
            cmd = [
                "clang", "-O2", "-g", "-Wall", "-target", "bpf",
                "-c", self.xdp_path, "-o", object_file
            ]
            subprocess.check_output(cmd, stderr=subprocess.STDOUT)
            return object_file
        except subprocess.SubprocessError as e:
            logger.error(f"Failed to compile XDP program: {e}")
            raise RuntimeError(f"XDP compilation failed: {e}")
    
    def load_xdp(self) -> bool:
        """
        Load the XDP program using BCC.
        
        Returns:
            True if successful, False otherwise
        """
        if HAVE_BCC:
            try:
                # Load the BPF program using BCC
                self.bpf = bcc.BPF(src_file=self.xdp_path)
                self.initialized = True
                return True
            except Exception as e:
                logger.error(f"Failed to load XDP program with BCC: {e}")
                # Fall back to libbpf approach below
        
        # Fallback to compiling manually and using libbpf-based tools
        try:
            self.object_file = self.compile_xdp()
            self.initialized = True
            return True
        except Exception as e:
            logger.error(f"Failed to load XDP program: {e}")
            return False
    
    def attach_xdp(self, interface: str, egress_interface: str = None) -> bool:
        """
        Attach the XDP program to an interface.
        
        Args:
            interface: The interface to attach the XDP program to
            egress_interface: The egress interface for packets (for redirection)
            
        Returns:
            True if successful, False otherwise
        """
        if not self.initialized and not self.load_xdp():
            logger.error("Cannot attach XDP program: initialization failed")
            return False
        
        ingress_idx = self.get_interface_index(interface)
        if not ingress_idx:
            logger.error(f"Interface {interface} not found")
            return False
        
        # Set up interface mapping if egress is provided
        if egress_interface:
            egress_idx = self.get_interface_index(egress_interface)
            if not egress_idx:
                logger.error(f"Egress interface {egress_interface} not found")
                return False
            
            self.update_interface_mapping(ingress_idx, egress_idx)
        
        # Attach the XDP program using BCC if available
        if HAVE_BCC and self.bpf:
            try:
                # Get XDP function from the BPF program
                xdp_fn = self.bpf.load_func("xdp_firewall_func", bcc.BPF.XDP)
                
                # Determine XDP mode
                flags = 0
                if self.use_generic:
                    flags = bcc.BPF.XDP_FLAGS_SKB_MODE  # Generic/SKB mode
                
                # Attach XDP function to the interface
                self.bpf.attach_xdp(interface, xdp_fn, flags)
                self.attached_interfaces[interface] = True
                logger.info(f"Attached XDP program to {interface}")
                return True
            except Exception as e:
                logger.error(f"Failed to attach XDP program to {interface} using BCC: {e}")
                # Fall back to ip command below
        
        # Fallback to using ip command
        try:
            mode = "xdpgeneric" if self.use_generic else "xdp"
            cmd = ["ip", "link", "set", "dev", interface, mode, "obj", self.object_file, "sec", "xdp"]
            subprocess.check_call(cmd)
            self.attached_interfaces[interface] = True
            logger.info(f"Attached XDP program to {interface} using ip command")
            return True
        except subprocess.SubprocessError as e:
            logger.error(f"Failed to attach XDP program to {interface}: {e}")
            
            # If native mode failed, try generic mode as a last resort
            if not self.use_generic:
                try:
                    logger.info(f"Trying generic XDP mode for {interface}")
                    cmd = ["ip", "link", "set", "dev", interface, "xdpgeneric", "obj", self.object_file, "sec", "xdp"]
                    subprocess.check_call(cmd)
                    self.attached_interfaces[interface] = True
                    logger.info(f"Attached XDP program to {interface} in generic mode")
                    return True
                except subprocess.SubprocessError as e2:
                    logger.error(f"Failed to attach XDP program to {interface} in generic mode: {e2}")
            
            return False
    
    def detach_xdp(self, interface: str) -> bool:
        """
        Detach the XDP program from an interface.
        
        Args:
            interface: The interface to detach the XDP program from
            
        Returns:
            True if successful, False otherwise
        """
        if not self.attached_interfaces.get(interface):
            logger.warning(f"XDP program not attached to {interface}")
            return True
        
        # Detach using BCC if available
        if HAVE_BCC and self.bpf:
            try:
                self.bpf.remove_xdp(interface, 0)
                del self.attached_interfaces[interface]
                logger.info(f"Detached XDP program from {interface}")
                return True
            except Exception as e:
                logger.error(f"Failed to detach XDP program from {interface} using BCC: {e}")
                # Fall back to ip command below
        
        # Fallback to using ip command
        try:
            mode = "xdpgeneric" if self.use_generic else "xdp"
            cmd = ["ip", "link", "set", "dev", interface, mode, "off"]
            subprocess.check_call(cmd)
            del self.attached_interfaces[interface]
            logger.info(f"Detached XDP program from {interface} using ip command")
            return True
        except subprocess.SubprocessError as e:
            logger.error(f"Failed to detach XDP program from {interface}: {e}")
            
            # Try the other mode as a fallback
            other_mode = "xdp" if mode == "xdpgeneric" else "xdpgeneric"
            try:
                cmd = ["ip", "link", "set", "dev", interface, other_mode, "off"]
                subprocess.check_call(cmd)
                del self.attached_interfaces[interface]
                logger.info(f"Detached XDP program from {interface} using {other_mode}")
                return True
            except subprocess.SubprocessError as e2:
                logger.error(f"Failed to detach XDP program from {interface} using {other_mode}: {e2}")
            
            return False
    
    def update_interface_mapping(self, ingress_ifindex: int, egress_ifindex: int, enabled: bool = True) -> bool:
        """
        Update the interface mapping in the iface_map BPF map.
        
        Args:
            ingress_ifindex: The index of the ingress interface
            egress_ifindex: The index of the egress interface
            enabled: Whether the mapping is enabled
            
        Returns:
            True if successful, False otherwise
        """
        if not self.initialized and not self.load_xdp():
            logger.error("Cannot update interface mapping: initialization failed")
            return False
        
        # Update using BCC if available
        if HAVE_BCC and self.bpf:
            try:
                iface_map = self.bpf.get_table("iface_map")
                
                # Create the map entry
                iface_entry = IfaceMap()
                iface_entry.ingress_ifindex = ingress_ifindex
                iface_entry.egress_ifindex = egress_ifindex
                iface_entry.enabled = 1 if enabled else 0
                
                # Update the map
                key = ctypes.c_uint32(ingress_ifindex)
                iface_map[key] = iface_entry
                
                # Also update tx_port map for redirects
                tx_port = self.bpf.get_table("tx_port")
                tx_port[ctypes.c_uint32(egress_ifindex)] = ctypes.c_uint32(egress_ifindex)
                
                logger.info(f"Updated interface mapping: {ingress_ifindex} -> {egress_ifindex}")
                return True
            except Exception as e:
                logger.error(f"Failed to update interface mapping using BCC: {e}")
                return False
        
        # Fallback to bpftool if BCC is not available
        try:
            # Create the map entry as bytes
            iface_entry = IfaceMap()
            iface_entry.ingress_ifindex = ingress_ifindex
            iface_entry.egress_ifindex = egress_ifindex
            iface_entry.enabled = 1 if enabled else 0
            
            # Use bpftool to update the map
            with open("/tmp/iface_map.bin", "wb") as f:
                f.write(bytes(iface_entry))
            
            # Find the map ID for iface_map
            cmd = ["bpftool", "map", "show", "name", "iface_map", "-j"]
            output = subprocess.check_output(cmd, text=True)
            map_info = json.loads(output)
            map_id = map_info[0]["id"]
            
            # Update the map
            cmd = [
                "bpftool", "map", "update", "id", str(map_id),
                "key", hex(ingress_ifindex), "value", "/tmp/iface_map.bin"
            ]
            subprocess.check_call(cmd)
            
            logger.info(f"Updated interface mapping using bpftool: {ingress_ifindex} -> {egress_ifindex}")
            return True
        except (subprocess.SubprocessError, json.JSONDecodeError, IndexError, KeyError) as e:
            logger.error(f"Failed to update interface mapping using bpftool: {e}")
            return False
    
    def update_sampling_config(self, config: Dict[str, int]) -> bool:
        """
        Update the sampling configuration in the sampling_config_map BPF map.
        
        Args:
            config: Dictionary containing sampling configuration
            
        Returns:
            True if successful, False otherwise
        """
        if not self.initialized and not self.load_xdp():
            logger.error("Cannot update sampling config: initialization failed")
            return False
        
        # Update using BCC if available
        if HAVE_BCC and self.bpf:
            try:
                sampling_map = self.bpf.get_table("sampling_config_map")
                
                # Create the map entry
                sampling_entry = SamplingConfig()
                sampling_entry.base_rate = config.get("base_rate", 100)  # 1%
                sampling_entry.syn_rate = config.get("syn_rate", 10)     # 10%
                sampling_entry.udp_rate = config.get("udp_rate", 50)     # 2%
                sampling_entry.icmp_rate = config.get("icmp_rate", 50)   # 2%
                sampling_entry.min_size = config.get("min_size", 64)
                sampling_entry.max_size = config.get("max_size", 1500)
                sampling_entry.size_rate = config.get("size_rate", 20)   # 5%
                
                # Update the map (always key 0 for this map)
                key = ctypes.c_uint32(0)
                sampling_map[key] = sampling_entry
                
                logger.info(f"Updated sampling configuration: base_rate={sampling_entry.base_rate}")
                return True
            except Exception as e:
                logger.error(f"Failed to update sampling configuration using BCC: {e}")
                return False
        
        # Fallback to bpftool if BCC is not available
        try:
            # Create the map entry as bytes
            sampling_entry = SamplingConfig()
            sampling_entry.base_rate = config.get("base_rate", 100)  # 1%
            sampling_entry.syn_rate = config.get("syn_rate", 10)     # 10%
            sampling_entry.udp_rate = config.get("udp_rate", 50)     # 2%
            sampling_entry.icmp_rate = config.get("icmp_rate", 50)   # 2%
            sampling_entry.min_size = config.get("min_size", 64)
            sampling_entry.max_size = config.get("max_size", 1500)
            sampling_entry.size_rate = config.get("size_rate", 20)   # 5%
            
            # Use bpftool to update the map
            with open("/tmp/sampling_config.bin", "wb") as f:
                f.write(bytes(sampling_entry))
            
            # Find the map ID for sampling_config_map
            cmd = ["bpftool", "map", "show", "name", "sampling_config_map", "-j"]
            output = subprocess.check_output(cmd, text=True)
            map_info = json.loads(output)
            map_id = map_info[0]["id"]
            
            # Update the map
            cmd = [
                "bpftool", "map", "update", "id", str(map_id),
                "key", "0", "value", "/tmp/sampling_config.bin"
            ]
            subprocess.check_call(cmd)
            
            logger.info(f"Updated sampling configuration using bpftool: base_rate={sampling_entry.base_rate}")
            return True
        except (subprocess.SubprocessError, json.JSONDecodeError, IndexError, KeyError) as e:
            logger.error(f"Failed to update sampling configuration using bpftool: {e}")
            return False
    
    def update_flow_verdict(self, 
                           src_ip: str, 
                           dst_ip: str, 
                           src_port: int = 0, 
                           dst_port: int = 0, 
                           protocol: int = 0,
                           action: int = VERDICT_ALLOW,
                           priority: int = 0,
                           rate_limit: int = 0) -> bool:
        """
        Update the verdict for a flow in the flow_verdict_map BPF map.
        
        Args:
            src_ip: Source IP address
            dst_ip: Destination IP address
            src_port: Source port
            dst_port: Destination port
            protocol: Protocol number
            action: Verdict action (VERDICT_UNKNOWN, VERDICT_ALLOW, VERDICT_BLOCK, VERDICT_RATE_LIMIT)
            priority: Priority level
            rate_limit: Rate limit value (if action is VERDICT_RATE_LIMIT)
            
        Returns:
            True if successful, False otherwise
        """
        if not self.initialized and not self.load_xdp():
            logger.error("Cannot update flow verdict: initialization failed")
            return False
        
        # Convert IP addresses to integers
        try:
            src_ip_int = struct.unpack("!I", bytes(map(int, src_ip.split("."))))[0]
            dst_ip_int = struct.unpack("!I", bytes(map(int, dst_ip.split("."))))[0]
        except Exception as e:
            logger.error(f"Failed to convert IP addresses: {e}")
            return False
        
        # Update using BCC if available
        if HAVE_BCC and self.bpf:
            try:
                verdict_map = self.bpf.get_table("flow_verdict_map")
                
                # Create the key
                flow_key = FlowKey()
                flow_key.src_ip = src_ip_int
                flow_key.dst_ip = dst_ip_int
                flow_key.src_port = src_port
                flow_key.dst_port = dst_port
                flow_key.protocol = protocol
                
                # Create the value
                flow_verdict = FlowVerdict()
                flow_verdict.action = action
                flow_verdict.priority = priority
                flow_verdict.timestamp = int(time.time())
                flow_verdict.packet_count = 0
                flow_verdict.byte_count = 0
                flow_verdict.rate_limit = rate_limit
                
                # Update the map
                verdict_map[flow_key] = flow_verdict
                
                logger.info(f"Updated flow verdict: {src_ip}:{src_port} -> {dst_ip}:{dst_port} = {action}")
                return True
            except Exception as e:
                logger.error(f"Failed to update flow verdict using BCC: {e}")
                return False
        
        # Fallback to bpftool if BCC is not available
        try:
            # Create the key as bytes
            flow_key = FlowKey()
            flow_key.src_ip = src_ip_int
            flow_key.dst_ip = dst_ip_int
            flow_key.src_port = src_port
            flow_key.dst_port = dst_port
            flow_key.protocol = protocol
            
            # Create the value as bytes
            flow_verdict = FlowVerdict()
            flow_verdict.action = action
            flow_verdict.priority = priority
            flow_verdict.timestamp = int(time.time())
            flow_verdict.packet_count = 0
            flow_verdict.byte_count = 0
            flow_verdict.rate_limit = rate_limit
            
            # Write key and value to temporary files
            with open("/tmp/flow_key.bin", "wb") as f:
                f.write(bytes(flow_key))
            
            with open("/tmp/flow_verdict.bin", "wb") as f:
                f.write(bytes(flow_verdict))
            
            # Find the map ID for flow_verdict_map
            cmd = ["bpftool", "map", "show", "name", "flow_verdict_map", "-j"]
            output = subprocess.check_output(cmd, text=True)
            map_info = json.loads(output)
            map_id = map_info[0]["id"]
            
            # Update the map
            cmd = [
                "bpftool", "map", "update", "id", str(map_id),
                "key", "/tmp/flow_key.bin", "value", "/tmp/flow_verdict.bin"
            ]
            subprocess.check_call(cmd)
            
            logger.info(f"Updated flow verdict using bpftool: {src_ip}:{src_port} -> {dst_ip}:{dst_port} = {action}")
            return True
        except (subprocess.SubprocessError, json.JSONDecodeError, IndexError, KeyError) as e:
            logger.error(f"Failed to update flow verdict using bpftool: {e}")
            return False
    
    def get_metrics(self) -> Optional[Dict[str, int]]:
        """
        Get metrics from the metrics_map BPF map.
        
        Returns:
            Dictionary of metrics, or None if failed
        """
        if not self.initialized and not self.load_xdp():
            logger.error("Cannot get metrics: initialization failed")
            return None
        
        # Get metrics using BCC if available
        if HAVE_BCC and self.bpf:
            try:
                metrics_map = self.bpf.get_table("metrics_map")
                key = ctypes.c_uint32(0)
                metrics = metrics_map[key]
                
                # Convert to dictionary
                return {
                    "total_packets": metrics.total_packets,
                    "allowed_packets": metrics.allowed_packets,
                    "blocked_packets": metrics.blocked_packets,
                    "sampled_packets": metrics.sampled_packets,
                    "syn_packets": metrics.syn_packets,
                    "udp_packets": metrics.udp_packets,
                    "icmp_packets": metrics.icmp_packets,
                    "other_packets": metrics.other_packets,
                }
            except Exception as e:
                logger.error(f"Failed to get metrics using BCC: {e}")
                return None
        
        # Fallback to bpftool if BCC is not available
        try:
            # Find the map ID for metrics_map
            cmd = ["bpftool", "map", "show", "name", "metrics_map", "-j"]
            output = subprocess.check_output(cmd, text=True)
            map_info = json.loads(output)
            map_id = map_info[0]["id"]
            
            # Get the value
            cmd = ["bpftool", "map", "lookup", "id", str(map_id), "key", "0", "-j"]
            output = subprocess.check_output(cmd, text=True)
            value_info = json.loads(output)
            
            # Parse the value
            if isinstance(value_info, dict) and "value" in value_info:
                value = value_info["value"]
                
                # Values are represented as a hex string
                total_packets = int(value[0:16], 16)
                allowed_packets = int(value[16:32], 16)
                blocked_packets = int(value[32:48], 16)
                sampled_packets = int(value[48:64], 16)
                syn_packets = int(value[64:80], 16)
                udp_packets = int(value[80:96], 16)
                icmp_packets = int(value[96:112], 16)
                other_packets = int(value[112:128], 16)
                
                return {
                    "total_packets": total_packets,
                    "allowed_packets": allowed_packets,
                    "blocked_packets": blocked_packets,
                    "sampled_packets": sampled_packets,
                    "syn_packets": syn_packets,
                    "udp_packets": udp_packets,
                    "icmp_packets": icmp_packets,
                    "other_packets": other_packets,
                }
            
            logger.error(f"Failed to parse metrics from bpftool: {value_info}")
            return None
        except (subprocess.SubprocessError, json.JSONDecodeError, IndexError, KeyError) as e:
            logger.error(f"Failed to get metrics using bpftool: {e}")
            return None
    
    def cleanup(self):
        """Clean up resources and detach XDP programs."""
        for interface in list(self.attached_interfaces.keys()):
            self.detach_xdp(interface)
        
        # Clean up temporary files
        try:
            for filename in [
                "/tmp/flow_key.bin", 
                "/tmp/flow_verdict.bin", 
                "/tmp/sampling_config.bin",
                "/tmp/iface_map.bin"
            ]:
                if os.path.exists(filename):
                    os.unlink(filename)
        except Exception as e:
            logger.error(f"Failed to clean up temporary files: {e}")
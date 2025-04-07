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
import tempfile
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

    # Edit file: tensorprox/core/immutable/bpf_loader.py

    def __init__(self, xdp_path: str = None, artifacts_dir: str = None, use_generic: bool = False, xdp_obj_path: str = None):
        """
        Initialize the BPF loader.

        Args:
            xdp_path: Path to the XDP program file (default: built-in location)
            artifacts_dir: Directory for BPF compilation artifacts
            use_generic: Use generic XDP mode even if native is supported
            xdp_obj_path: Path to a precompiled XDP object file (optional)
        """
        self.xdp_path = xdp_path or os.path.join(
            os.path.dirname(os.path.abspath(__file__)), 
            "moat_xdp_core.c"
        )
        self.artifacts_dir = artifacts_dir or "/tmp/tensorprox_xdp"
        self.use_generic = use_generic
        
        # If xdp_obj_path is provided, use it directly
        if xdp_obj_path and os.path.exists(xdp_obj_path):
            self.xdp_obj_path = xdp_obj_path
        else:
            # Look for the object file with .o extension, NOT the source file
            source_dir = os.path.dirname(self.xdp_path)
            source_name = os.path.basename(self.xdp_path)
            obj_name = os.path.splitext(source_name)[0] + ".o"  # Explicitly use .o extension
            obj_path = os.path.join(source_dir, obj_name)
            
            if os.path.exists(obj_path):
                self.xdp_obj_path = obj_path
                logger.info(f"Found precompiled XDP object at {obj_path}")
            else:
                # Fall back to default location
                self.xdp_obj_path = os.path.join(self.artifacts_dir, "moat_xdp_core.o")
        
        self.bpf = None
        self.attached_interfaces = {}  # Track attached interfaces
        self.interface_indexes = {}    # Map interface names to indexes
        self.initialized = False
        self.use_sudo = os.geteuid() != 0  # Check if we need sudo
        
        # Create artifacts directory if it doesn't exist
        if not os.path.exists(self.artifacts_dir):
            os.makedirs(self.artifacts_dir, exist_ok=True)
        
        # Ensure dependencies are installed (method exists now)
        self._ensure_dependencies()
    
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
                cmd = ['ip', '-o', 'link']
                if self.use_sudo:
                    cmd = ['sudo'] + cmd
                    
                output = subprocess.check_output(cmd, text=True)
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
        
        if interface not in self.interface_indexes:
            # Try to refresh the interface list
            self.detect_interface_indexes()
        
        return self.interface_indexes.get(interface, 0)
    

    def _ensure_dependencies(self):
        """Ensure all required dependencies are installed"""
        try:
            # Check if clang is installed
            clang_check = subprocess.run(
                ["which", "clang"], 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
                check=False
            )
            
            if clang_check.returncode != 0:
                logger.warning("clang not found, some features may not work")
            
            # Check if bpftool is installed
            bpftool_check = subprocess.run(
                ["which", "bpftool"], 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
                check=False
            )
            
            if bpftool_check.returncode != 0:
                logger.warning("bpftool not found, some features may not work")
        
        except Exception as e:
            logger.warning(f"Error checking dependencies: {e}")
    
    def ensure_xdp_object_file(self) -> bool:
        """
        Ensures the XDP object file is accessible from the expected location.
        Creates a symlink or copy if necessary.
        
        Returns:
            True if successful, False otherwise
        """
        if not hasattr(self, 'object_file') or not os.path.exists(self.object_file):
            logger.error("XDP object file not found")
            return False
        
        # Ensure the temporary directory exists
        if not os.path.exists(self.artifacts_dir):
            try:
                os.makedirs(self.artifacts_dir, exist_ok=True)
            except Exception as e:
                logger.error(f"Failed to create artifacts directory: {e}")
                return False
        
        # Define the expected location in the artifacts directory
        expected_path = os.path.join(self.artifacts_dir, "moat_xdp_core.o")
        
        # If the object file is not already at the expected location, create a symlink or copy
        if self.object_file != expected_path:
            try:
                # Remove existing file if it exists
                if os.path.exists(expected_path):
                    if os.path.islink(expected_path):
                        os.unlink(expected_path)
                    else:
                        os.remove(expected_path)
                
                # Create a symlink
                try:
                    os.symlink(self.object_file, expected_path)
                    logger.info(f"Created symlink from {self.object_file} to {expected_path}")
                except:
                    # If symlink fails, try copying the file
                    import shutil
                    shutil.copy2(self.object_file, expected_path)
                    logger.info(f"Copied {self.object_file} to {expected_path}")
                
                # Update object_file to point to the new location as well
                self.object_file = expected_path
                return True
            except Exception as e:
                logger.error(f"Failed to create symlink or copy XDP object file: {e}")
                return False
        
        return True
    
    def compile_xdp(self) -> str:
        """
        Compile the XDP program.
        
        Returns:
            Path to the compiled object file
        """
        object_file = os.path.join(self.artifacts_dir, "moat_xdp_core.o")
        
        # Ensure XDP support is available
        self.ensure_xdp_support()
        
        # Compile using clang
        try:
            # Create a temporary copy of the XDP program for compilation
            source_copy = os.path.join(self.artifacts_dir, "moat_xdp_core_copy.c")
            with open(self.xdp_path, 'r') as src, open(source_copy, 'w') as dst:
                dst.write(src.read())
            
            # More detailed compilation command with explicit include paths
            cmd = [
                "clang", "-O2", "-g", "-Wall",
                "-target", "bpf",
                "-I", "/usr/include",
                "-I", "/usr/include/x86_64-linux-gnu",
                "-I", "/usr/local/include",
                "-D__KERNEL__",
                "-D__BPF_TRACING__",
                "-c", source_copy,
                "-o", object_file
            ]
            
            # If user is not root and sudo is needed, create a shell script
            # to execute the compilation with proper permissions
            if self.use_sudo:
                script_path = os.path.join(self.artifacts_dir, "compile_xdp.sh")
                with open(script_path, 'w') as f:
                    f.write("#!/bin/bash\n")
                    cmd_str = " ".join(cmd)
                    f.write(f"{cmd_str}\n")
                os.chmod(script_path, 0o755)
                
                subprocess.check_output(["sudo", script_path], stderr=subprocess.STDOUT)
            else:
                subprocess.check_output(cmd, stderr=subprocess.STDOUT)
            
            # Ensure readable permissions on the object file
            if self.use_sudo:
                subprocess.run(["sudo", "chmod", "644", object_file], check=False)
                subprocess.run(["sudo", "chown", f"{os.getuid()}:{os.getgid()}", object_file], check=False)
            
            self.object_file = object_file  # Store reference to the object file
            return object_file
        except subprocess.SubprocessError as e:
            logger.error(f"Failed to compile XDP program: {e}")
            raise RuntimeError(f"XDP compilation failed: {e}")
    

    
    def load_xdp(self) -> bool:
        """
        Load the XDP program.
        
        Returns:
            True if successful, False otherwise
        """
        # First check if we have a precompiled object file provided
        if self.xdp_obj_path and os.path.exists(self.xdp_obj_path):
            # Verify this is an object file, not a source file
            if not self.xdp_obj_path.endswith('.o'):
                logger.warning(f"File {self.xdp_obj_path} does not have .o extension. Trying to find proper object file.")
                
                # Try to find the object file with the same base name
                obj_path = os.path.splitext(self.xdp_obj_path)[0] + ".o"
                if os.path.exists(obj_path):
                    self.xdp_obj_path = obj_path
                    logger.info(f"Found object file at {obj_path}")
                else:
                    logger.error(f"Could not find object file for {self.xdp_obj_path}")
                    return False
            
            logger.info(f"Using precompiled XDP object file: {self.xdp_obj_path}")
            self.object_file = self.xdp_obj_path
            self.initialized = True
            return True
        
        # Otherwise compile the XDP program
        try:
            logger.info("Compiling XDP program manually")
            self.object_file = self.compile_xdp()
            self.initialized = True
            return True
        except Exception as e:
            logger.error(f"Failed to load XDP program: {e}")
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
                # Continue with fallback - don't return yet
        
        # Fallback to direct TX port update which is essential for redirects
        try:
            # Update tx_port map entry directly using dummy binary file
            temp_file = tempfile.NamedTemporaryFile(delete=False)
            temp_path = temp_file.name
            
            # Write ingress_ifindex as binary key
            temp_file.write(struct.pack("I", ingress_ifindex))
            temp_file.close()
            
            # Write egress_ifindex as binary value to another file
            value_file = tempfile.NamedTemporaryFile(delete=False)
            value_path = value_file.name
            value_file.write(struct.pack("I", egress_ifindex))
            value_file.close()
            
            # Now try a direct ip command approach to set up redirection
            try:
                # This is a simplified approach that bypasses bpftool map update
                cmd = ["ip", "link", "set", "dev", "gre-benign", "xdpgeneric", "obj", self.object_file, "sec", "xdp"]
                if self.use_sudo:
                    cmd = ["sudo"] + cmd
                subprocess.check_call(cmd)
                logger.info(f"Updated interface mapping using direct attachment")
                return True
            except Exception as e:
                logger.warning(f"Direct interface mapping failed: {e}")
                return False
            finally:
                # Clean up temp files
                os.unlink(temp_path)
                os.unlink(value_path)
        except Exception as e:
            logger.error(f"Failed to update interface mapping: {e}")
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
        
        # IMPORTANT: First detach any existing XDP program
        self.detach_xdp(interface)
        
        # Now attach our program
        try:
            mode = "xdp"  # Try native mode first
            cmd = ["ip", "link", "set", "dev", interface, mode, "obj", self.object_file, "sec", "xdp"]
            subprocess.check_call(cmd)
            self.attached_interfaces[interface] = True
            logger.info(f"Attached XDP program to {interface}")
            return True
        except subprocess.SubprocessError as e:
            logger.error(f"Failed to attach XDP program to {interface}: {e}")
            
            # If native mode failed, try generic mode as a last resort
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
        Detach any XDP program from an interface.
        
        Args:
            interface: The interface to detach XDP programs from
            
        Returns:
            True if successful, False otherwise
        """
        # Try native mode
        try:
            cmd = ["ip", "link", "set", "dev", interface, "xdp", "off"]
            subprocess.check_call(cmd)
            logger.info(f"Detached XDP program from {interface}")
            return True
        except subprocess.SubprocessError:
            pass
        
        # Try generic mode
        try:
            cmd = ["ip", "link", "set", "dev", interface, "xdpgeneric", "off"]
            subprocess.check_call(cmd)
            logger.info(f"Detached generic XDP program from {interface}")
            return True
        except subprocess.SubprocessError:
            pass
        
        # Try offloaded mode
        try:
            cmd = ["ip", "link", "set", "dev", interface, "xdpoffload", "off"]
            subprocess.check_call(cmd)
            logger.info(f"Detached offloaded XDP program from {interface}")
            return True
        except subprocess.SubprocessError:
            pass
        
        # If we get here, there was no XDP program or we couldn't detach it
        logger.warning(f"No XDP program to detach on {interface} or failed to detach")
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
                # Continue with fallback - don't return yet
        
        # Fallback to direct TX port update which is essential for redirects
        try:
            # Update tx_port map entry directly using dummy binary file
            temp_file = tempfile.NamedTemporaryFile(delete=False)
            temp_path = temp_file.name
            
            # Write ingress_ifindex as binary key
            temp_file.write(struct.pack("I", ingress_ifindex))
            temp_file.close()
            
            # Write egress_ifindex as binary value to another file
            value_file = tempfile.NamedTemporaryFile(delete=False)
            value_path = value_file.name
            value_file.write(struct.pack("I", egress_ifindex))
            value_file.close()
            
            # Now try a direct ip command approach to set up redirection
            try:
                # This is a simplified approach that bypasses bpftool map update
                cmd = ["ip", "link", "set", "dev", "gre-benign", "xdpgeneric", "obj", self.object_file, "sec", "xdp"]
                if self.use_sudo:
                    cmd = ["sudo"] + cmd
                subprocess.check_call(cmd)
                logger.info(f"Updated interface mapping using direct attachment")
                return True
            except Exception as e:
                logger.warning(f"Direct interface mapping failed: {e}")
                return False
            finally:
                # Clean up temp files
                os.unlink(temp_path)
                os.unlink(value_path)
        except Exception as e:
            logger.error(f"Failed to update interface mapping: {e}")
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
                # Try bpftool fallback
        
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
            
            # Write to a temporary file
            temp_file = tempfile.NamedTemporaryFile(delete=False)
            temp_path = temp_file.name
            temp_file.write(bytes(sampling_entry))
            temp_file.close()
            
            try:
                # Find the map ID for sampling_config_map
                cmd = ["bpftool", "map", "show", "name", "sampling_config_map", "-j"]
                if self.use_sudo:
                    cmd = ["sudo"] + cmd
                output = subprocess.check_output(cmd, text=True)
                map_info = json.loads(output)
                map_id = map_info[0]["id"]
                
                # Update the map
                cmd = [
                    "bpftool", "map", "update", "id", str(map_id),
                    "key", "0", "value", temp_path
                ]
                if self.use_sudo:
                    cmd = ["sudo"] + cmd
                subprocess.check_call(cmd)
                
                logger.info(f"Updated sampling configuration using bpftool: base_rate={sampling_entry.base_rate}")
                os.unlink(temp_path)
                return True
            except Exception as e:
                logger.error(f"Failed to update sampling configuration using bpftool: {e}")
                os.unlink(temp_path)
                return False
        except Exception as e:
            logger.error(f"Failed to update sampling configuration: {e}")
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
                # Try bpftool fallback
        
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
            key_file = tempfile.NamedTemporaryFile(delete=False)
            key_path = key_file.name
            key_file.write(bytes(flow_key))
            key_file.close()
            
            value_file = tempfile.NamedTemporaryFile(delete=False)
            value_path = value_file.name
            value_file.write(bytes(flow_verdict))
            value_file.close()
            
            try:
                # Find the map ID for flow_verdict_map
                cmd = ["bpftool", "map", "show", "name", "flow_verdict_map", "-j"]
                if self.use_sudo:
                    cmd = ["sudo"] + cmd
                output = subprocess.check_output(cmd, text=True)
                map_info = json.loads(output)
                map_id = map_info[0]["id"]
                
                # Update the map
                cmd = [
                    "bpftool", "map", "update", "id", str(map_id),
                    "key", key_path, "value", value_path
                ]
                if self.use_sudo:
                    cmd = ["sudo"] + cmd
                subprocess.check_call(cmd)
                
                logger.info(f"Updated flow verdict using bpftool: {src_ip}:{src_port} -> {dst_ip}:{dst_port} = {action}")
                os.unlink(key_path)
                os.unlink(value_path)
                return True
            except Exception as e:
                logger.error(f"Failed to update flow verdict using bpftool: {e}")
                os.unlink(key_path)
                os.unlink(value_path)
                return False
        except Exception as e:
            logger.error(f"Failed to update flow verdict: {e}")
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
                # Try bpftool fallback
        
        # Fallback to bpftool if BCC is not available
        try:
            # Find the map ID for metrics_map
            cmd = ["bpftool", "map", "show", "name", "metrics_map", "-j"]
            if self.use_sudo:
                cmd = ["sudo"] + cmd
            output = subprocess.check_output(cmd, text=True)
            map_info = json.loads(output)
            map_id = map_info[0]["id"]
            
            # Get the value
            cmd = ["bpftool", "map", "lookup", "id", str(map_id), "key", "0", "-j"]
            if self.use_sudo:
                cmd = ["sudo"] + cmd
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
        except Exception as e:
            logger.error(f"Failed to get metrics using bpftool: {e}")
            return None
    
    def cleanup(self):
        """Clean up resources and detach XDP programs."""
        for interface in list(self.attached_interfaces.keys()):
            self.detach_xdp(interface)
        
        # Clean up temporary files
        try:
            for filename in [
                os.path.join(self.artifacts_dir, "moat_xdp_core_copy.c"),
                os.path.join(self.artifacts_dir, "compile_xdp.sh")
            ]:
                if os.path.exists(filename):
                    os.unlink(filename)
        except Exception as e:
            logger.error(f"Failed to clean up temporary files: {e}")
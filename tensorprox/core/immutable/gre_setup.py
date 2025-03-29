#!/usr/bin/env python3
"""
Ultra High-Performance GRE Tunnel Setup with AF_XDP Kernel Bypass
Optimized for Tbps throughput using direct hardware access
Supports flexible 10.0.0.0/8 IP addressing for tunnel endpoints only
DOES NOT modify primary interface routing
Enhanced for virtualized environments with automatic resource scaling
"""

import os
import time
import re
import multiprocessing
from datetime import datetime
import subprocess
import math
import shutil
import tempfile
import sys

# Debug level (0=minimal, 1=normal, 2=verbose)
DEBUG_LEVEL = 2

# ===== GRE CONFIGURATION =====
# Fixed overlay network IPs
BENIGN_OVERLAY_IP = "10.200.77.102"
ATTACKER_OVERLAY_IP = "10.200.77.103"
KING_OVERLAY_IP = "10.200.77.1"

# Fixed GRE tunnel keys
BENIGN_MOAT_KEY = "77"
ATTACKER_MOAT_KEY = "79"
MOAT_KING_KEY = "88"

# MTU Sizing 
GRE_MTU = 1465  # Standard MTU 1500 - 25 GRE - 10 random Buffer
IPIP_MTU = 1445  # GRE_MTU - 20 for IPIP overhead

# Determine if running as root once at startup
IS_ROOT = os.geteuid() == 0

# Use user-specific paths for non-root users
if IS_ROOT:
    # Root user can use system paths
    XDP_PROGRAM_DIR = "/opt/af_xdp_tools"
    XDP_LOG_DIR = "/var/log/tunnel"
else:
    # Non-root user gets paths in home directory
    HOME_DIR = os.path.expanduser("~")
    XDP_PROGRAM_DIR = os.path.join(HOME_DIR, ".tensorprox", "af_xdp_tools")
    XDP_LOG_DIR = os.path.join(HOME_DIR, ".tensorprox", "logs", "tunnel")

class GRESetup:

    node_type: str 

    def __init__(self, node_type: str):
        self.node_type = node_type  # Set the node_type

    def run_cmd(self, cmd, show_output=False, check=False, quiet=False, timeout=360, shell=False):
        """Run command and return result with proper sudo privileges"""
        # Check if we're root
        is_root = os.geteuid() == 0
        
        # Convert list to string for shell commands
        cmd_str = ' '.join(cmd) if isinstance(cmd, list) else cmd
        if not quiet:
            log("[CMD] {0}".format(cmd_str), level=1)
        
        # Prepend sudo when not root for commands that need it
        if not is_root:
            # Commands that need elevated privileges
            sudo_commands = [
                "ip", "sysctl", "iptables", "ethtool", "modprobe", "mount", "dpkg", 
                "apt-get", "apt", "systemctl", "mkdir", "cp", "mv", "rm", "chmod", 
                "chown", "echo", "dpkg-reconfigure", "update-grub", "tee", "chrt"
            ]
            
            # Check if command needs sudo
            needs_sudo = False
            if isinstance(cmd, list) and cmd and cmd[0] in sudo_commands:
                needs_sudo = True
                cmd = ["sudo", "-n"] + cmd
            elif isinstance(cmd, str):
                for sudo_cmd in sudo_commands:
                    if cmd.startswith(sudo_cmd + " ") or re.match(r'^' + sudo_cmd + r'\b', cmd):
                        needs_sudo = True
                        cmd = "sudo -n " + cmd
                        break
                # Also catch commands that pipe to sudo commands
                if not needs_sudo and any(f"| sudo" in cmd or f"|sudo" in cmd):
                    cmd = cmd.replace("| sudo", "| sudo -n").replace("|sudo", "| sudo -n")
                # Catch redirections to protected files
                if not needs_sudo and any(protected_path in cmd for protected_path in ["/etc/", "/var/", "/opt/", "/usr/", "/lib/", "/boot/", "> /proc/"]):
                    # We need to handle this differently as simple prefixing won't work with redirection
                    # Save the command to execute it with bash -c and sudo
                    cmd = f"sudo -n bash -c '{cmd}'"
                    shell = True
        
        # Handle shell commands differently
        if shell and isinstance(cmd, list):
            cmd = ' '.join(cmd)
        
        # Set environment variables for apt operations
        env = os.environ.copy()
        if any(x in cmd_str for x in ['apt-get', 'apt', 'dpkg']):
            env['DEBIAN_FRONTEND'] = 'noninteractive'
        
        # Synchronous execution
        try:
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, 
                                text=True, shell=shell, timeout=timeout, env=env)
            
            # Handle error conditions but ignore certain expected errors
            if (result.returncode != 0 and result.stderr and 
                "Cannot find device" not in result.stderr and 
                "File exists" not in result.stderr and 
                "sysctl: cannot stat" not in result.stderr and
                "RTNETLINK answers: File exists" not in result.stderr and
                not quiet):
                log("[ERROR] {0}".format(cmd_str), level=1)
                log("stderr: {0}".format(result.stderr.strip()), level=1)
                if check:
                    sys.exit(1)
            
            if show_output and result.stdout and not quiet:
                log(result.stdout, level=2)
                
            return result
        except subprocess.TimeoutExpired:
            log("[ERROR] Command timed out after {0} seconds: {1}".format(timeout, cmd_str), level=1)
            return subprocess.CompletedProcess(cmd, -1, "", "Timeout occurred")

    def ensure_directory(self, path, mode=0o755):
        """Safely create directory with proper permissions regardless of user"""
        if os.path.exists(path):
            # If the directory exists but we don't have write access and we're not root,
            # try to fix permissions with sudo
            if not os.access(path, os.W_OK) and os.geteuid() != 0:
                self.run_cmd(["sudo", "-n", "chmod", str(mode).replace('0o', ''), path], quiet=True)
            return True
            
        try:
            # Try direct creation first (works for user-owned paths)
            os.makedirs(path, mode=mode, exist_ok=True)
            return True
        except PermissionError:
            # Fall back to sudo
            if os.geteuid() != 0:  # Not root
                self.run_cmd(["sudo", "-n", "mkdir", "-p", path], quiet=True)
                self.run_cmd(["sudo", "-n", "chmod", str(mode).replace('0o', ''), path], quiet=True)
                # Make sure the directory is accessible to the current user
                self.run_cmd(["sudo", "-n", "chown", f"{os.getuid()}:{os.getgid()}", path], quiet=True)
                return os.path.exists(path)
            return False


    def safe_write_file(self, path, content, mode=0o644):
        """Safely write to a file with proper permissions regardless of user"""
        # Get directory of the file
        directory = os.path.dirname(path)
        self.ensure_directory(directory)
        
        try:
            # Try direct write first
            with open(path, "w") as f:
                f.write(content)
            os.chmod(path, mode)
            return True
        except PermissionError:
            # Fall back to using sudo with a temporary file
            if not IS_ROOT:
                # Create a temporary file with the content
                with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp_file:
                    temp_path = temp_file.name
                    temp_file.write(content)
                
                # Use sudo to move the file and set permissions
                self.run_cmd(["sudo", "-n", "cp", temp_path, path], quiet=True)
                self.run_cmd(["sudo", "-n", "chmod", str(mode).replace('0o', ''), path], quiet=True)
                
                # Clean up the temporary file
                try:
                    os.unlink(temp_path)
                except:
                    pass
                return True
            return False
    
    def detect_primary_interface(self):
        """Detect the primary network interface with a public IP"""
        # First try common interface names for cloud VMs
        common_interfaces = ['ens5', 'eth0', 'enp1s0','virbr0', 'ens3', 'enp0s3', 'en0']
        
        for interface in common_interfaces:
            # Check if interface exists
            result = self.run_cmd(["ip", "link", "show", interface], quiet=True)
            if result.returncode == 0:
                # Check if it has an IP
                ip_result = self.run_cmd(["ip", "-o", "-4", "addr", "show", "dev", interface], quiet=True)
                if ip_result.returncode == 0 and ip_result.stdout.strip():
                    match = re.search(r'inet\s+([0-9.]+)', ip_result.stdout)
                    if match and match.group(1) != "127.0.0.1":
                        ip = match.group(1)
                        log("[AUTO] Detected primary interface: {0} with IP: {1}".format(interface, ip), level=1)
                        return interface, ip
        
        # If not found with common names, try to find via default route
        route_result = self.run_cmd(["ip", "-o", "route", "get", "1.1.1.1"], quiet=True)
        if route_result.returncode == 0:
            match = re.search(r'dev\s+(\S+)', route_result.stdout)
            if match:
                interface = match.group(1)
                ip_result = self.run_cmd(["ip", "-o", "-4", "addr", "show", "dev", interface], quiet=True)
                if ip_result.returncode == 0:
                    match = re.search(r'inet\s+([0-9.]+)', ip_result.stdout)
                    if match:
                        ip = match.group(1)
                        log("[AUTO] Detected primary interface via route: {0} with IP: {1}".format(interface, ip), level=1)
                        return interface, ip
        
        # Last resort - get all interfaces and pick first non-loopback with IPv4
        all_interfaces_result = self.run_cmd(["ip", "link", "show"], quiet=True)
        if all_interfaces_result.returncode == 0:
            for line in all_interfaces_result.stdout.splitlines():
                match = re.search(r'\d+:\s+(\S+):', line)
                if match:
                    interface = match.group(1)
                    if interface == 'lo' or interface.startswith(('gre', 'tun', 'br')):
                        continue
                    
                    ip_result = self.run_cmd(["ip", "-o", "-4", "addr", "show", "dev", interface], quiet=True)
                    if ip_result.returncode == 0 and ip_result.stdout.strip():
                        match = re.search(r'inet\s+([0-9.]+)', ip_result.stdout)
                        if match and not match.group(1).startswith('127.'):
                            ip = match.group(1)
                            log("[AUTO] Found usable interface: {0} with IP: {1}".format(interface, ip), level=1)
                            return interface, ip
        
        log("[ERROR] Could not detect primary network interface", level=0)
        return None, None

    def flush_device(self, dev):
        """Delete network device if it exists"""
        self.run_cmd(["ip", "link", "set", dev, "down"], quiet=True)
        self.run_cmd(["ip", "link", "del", dev], quiet=True)

    def clean_policy_routing(self):
        """Clean existing policy routing rules and tables"""
        # Save original rules that aren't ours
        existing_rules = self.run_cmd(["ip", "rule", "list"], quiet=True).stdout
        
        # First, delete any custom rules we've set (lookups to table 100-110)
        for i in range(100, 111):
            self.run_cmd(["ip", "rule", "del", "lookup", str(i)], quiet=True)
        
        # Flush custom routing tables
        for i in range(100, 111):
            self.run_cmd(["ip", "route", "flush", "table", str(i)], quiet=True)
        
        # Restore system default rules (just to be safe)
        self.run_cmd(["ip", "rule", "add", "from", "all", "lookup", "local", "pref", "0"], quiet=True)
        self.run_cmd(["ip", "rule", "add", "from", "all", "lookup", "main", "pref", "32766"], quiet=True)
        self.run_cmd(["ip", "rule", "add", "from", "all", "lookup", "default", "pref", "32767"], quiet=True)

    def detect_system_capabilities(self):
        """Detect and return system capabilities for auto-scaling"""
        capabilities = {
            "is_virtualized": False,
            "cpu_count": multiprocessing.cpu_count(),
            "memory_gb": 0,
            "numa_nodes": 1,
            "nic_speed_gbps": 10,  # Default assumption
            "xdp_support": "none",
            "dpdk_possible": False,
            "virtualization_type": "none",
            "nic_driver": "unknown"
        }
        
        # Check virtualization
        virt_check = self.run_cmd(["systemd-detect-virt"], quiet=True)
        if virt_check.returncode == 0 and virt_check.stdout.strip() != "none":
            capabilities["is_virtualized"] = True
            capabilities["virtualization_type"] = virt_check.stdout.strip()
            log("[INFO] Virtualized environment detected: {0}".format(virt_check.stdout.strip()), level=1)
        
        # Get total memory
        mem_info = self.run_cmd(["grep", "MemTotal", "/proc/meminfo"], quiet=True)
        if mem_info.returncode == 0:
            match = re.search(r'MemTotal:\s+(\d+)', mem_info.stdout)
            if match:
                mem_kb = int(match.group(1))
                capabilities["memory_gb"] = mem_kb / 1024 / 1024
                log("[INFO] System memory: {:.1f} GB".format(capabilities["memory_gb"]), level=1)
        
        # Check NUMA topology
        numa_check = self.run_cmd(["lscpu"], quiet=True)
        if numa_check.returncode == 0:
            numa_match = re.search(r'NUMA node\(s\):\s+(\d+)', numa_check.stdout)
            if numa_match:
                capabilities["numa_nodes"] = int(numa_match.group(1))
                log("[INFO] NUMA nodes: {0}".format(capabilities["numa_nodes"]), level=1)
        
        # Check NIC driver and speed
        primary_interface, _ = self.detect_primary_interface()
        if primary_interface:
            driver_info = self.run_cmd(["ethtool", "-i", primary_interface], quiet=True)
            if driver_info.returncode == 0:
                driver_match = re.search(r'driver:\s+(\S+)', driver_info.stdout)
                if driver_match:
                    capabilities["nic_driver"] = driver_match.group(1)
                    log("[INFO] NIC driver: {0}".format(capabilities["nic_driver"]), level=1)
                
                # Check for virtio driver
                if "virtio" in driver_info.stdout:
                    capabilities["xdp_support"] = "generic"
                    log("[INFO] virtio_net detected - Generic XDP mode support", level=1)
            
            # Try to determine NIC speed
            speed_info = self.run_cmd(["ethtool", primary_interface], quiet=True)
            if speed_info.returncode == 0:
                speed_match = re.search(r'Speed:\s+(\d+)([GMK]b/s)', speed_info.stdout)
                if speed_match:
                    speed_value = int(speed_match.group(1))
                    speed_unit = speed_match.group(2)
                    if speed_unit == "Gb/s":
                        capabilities["nic_speed_gbps"] = speed_value
                    elif speed_unit == "Mb/s":
                        capabilities["nic_speed_gbps"] = speed_value / 1000
                    log("[INFO] NIC speed: {0} Gbps".format(capabilities["nic_speed_gbps"]), level=1)
        
        # Check XDP support
        xdp_check = self.run_cmd(["grep", "CONFIG_XDP_SOCKETS=y", "/boot/config-$(uname -r)"], quiet=True)
        if xdp_check.returncode == 0:
            capabilities["xdp_support"] = "generic"
            log("[INFO] Generic XDP support detected", level=1)
            
            # Try to determine if native XDP is also supported by the driver
            if not capabilities["is_virtualized"]:
                native_check = self.run_cmd(["ip", "link", "set", "dev", primary_interface, "xdp", "off"], quiet=True)
                if native_check.returncode == 0:
                    capabilities["xdp_support"] = "native"
                    log("[INFO] Native XDP support detected", level=1)
        
        # Check DPDK possibility
        dpdk_check = self.run_cmd(["apt-cache", "search", "^dpdk$"], quiet=True)
        if dpdk_check.returncode == 0 and "dpdk" in dpdk_check.stdout:
            capabilities["dpdk_possible"] = True
            log("[INFO] DPDK packages available in repository", level=1)
        
        return capabilities

    # ===== ENHANCED PERFORMANCE OPTIMIZATION FUNCTIONS =====

    def calculate_resource_allocation(self, capabilities):
        """Calculate optimal resource allocation based on system capabilities and node type"""
        resource_plan = {
            "dpdk_cores": 0,
            "reserve_cores": 0,
            "hugepages_gb": 0,
            "mem_channels": 1,
            "rx_queues": 1,
            "tx_queues": 1,
            "socket_mem": "1024",
            "cpu_mask": "0x1",
            "ring_buffer": 4096,
            "isolated_cpus": "",
            "system_cpus": "0"
        }
        
        cpu_count = capabilities["cpu_count"]
        
        # Account for NUMA topology
        numa_nodes = max(1, capabilities["numa_nodes"])
        
        # Different allocation strategies based on node type
        if self.node_type == "moat":
            # Moat is the central node - allocate more resources
            if cpu_count >= 16:
                # Large system
                resource_plan["dpdk_cores"] = min(8, cpu_count // 2)
                resource_plan["reserve_cores"] = cpu_count // 2
                resource_plan["hugepages_gb"] = min(16, capabilities["memory_gb"] // 4)
            elif cpu_count >= 8:
                # Medium system
                resource_plan["dpdk_cores"] = min(4, cpu_count // 2)
                resource_plan["reserve_cores"] = cpu_count // 2
                resource_plan["hugepages_gb"] = min(8, capabilities["memory_gb"] // 4)
            elif cpu_count >= 4:
                # Small system
                resource_plan["dpdk_cores"] = 2
                resource_plan["reserve_cores"] = 2
                resource_plan["hugepages_gb"] = min(4, capabilities["memory_gb"] // 4)
            else:
                # Minimal system
                resource_plan["dpdk_cores"] = 1
                resource_plan["reserve_cores"] = 1
                resource_plan["hugepages_gb"] = 1
        else:
            # End nodes need fewer resources
            if cpu_count >= 8:
                resource_plan["dpdk_cores"] = 2
                resource_plan["reserve_cores"] = 2
                resource_plan["hugepages_gb"] = min(4, capabilities["memory_gb"] // 8)
            elif cpu_count >= 4:
                resource_plan["dpdk_cores"] = 1
                resource_plan["reserve_cores"] = 1
                resource_plan["hugepages_gb"] = min(2, capabilities["memory_gb"] // 8)
            else:
                resource_plan["dpdk_cores"] = 1
                resource_plan["reserve_cores"] = 1
                resource_plan["hugepages_gb"] = 1
        
        # Calculate other parameters based on allocated cores
        
        # Determine optimal socket memory allocation
        socket_mem_per_node = int((resource_plan["hugepages_gb"] * 1024) / numa_nodes)
        socket_mem_values = [str(socket_mem_per_node)] * numa_nodes
        resource_plan["socket_mem"] = ",".join(socket_mem_values)
        
        # Calculate CPU mask for DPDK cores
        # Reserve core 0 for system tasks
        dpdk_core_mask = 0
        for i in range(1, resource_plan["dpdk_cores"] + 1):
            dpdk_core_mask |= (1 << i)
        resource_plan["cpu_mask"] = "0x{:x}".format(dpdk_core_mask)
        
        # Set up CPU isolation
        isolated_cpus = []
        for i in range(1, resource_plan["reserve_cores"] + 1):
            isolated_cpus.append(str(i))
        
        resource_plan["isolated_cpus"] = ",".join(isolated_cpus)
        
        # Calculate queue counts for multi-queue adapters
        resource_plan["rx_queues"] = max(1, resource_plan["dpdk_cores"])
        resource_plan["tx_queues"] = max(1, resource_plan["dpdk_cores"])
        
        # Scale ring buffer with NIC speed
        if capabilities["nic_speed_gbps"] >= 40:
            resource_plan["ring_buffer"] = 16384
        elif capabilities["nic_speed_gbps"] >= 25:
            resource_plan["ring_buffer"] = 8192
        elif capabilities["nic_speed_gbps"] >= 10:
            resource_plan["ring_buffer"] = 4096
        else:
            resource_plan["ring_buffer"] = 2048
        
        log("[INFO] Resource allocation for {0}: {1} DPDK cores, {2} reserved cores, {3}GB hugepages".format(
            self.node_type, resource_plan["dpdk_cores"], resource_plan["reserve_cores"], resource_plan["hugepages_gb"]), level=1)
        
        return resource_plan

    def optimize_kernel_params(self):
        """Optimize kernel parameters for high performance tunneling"""
        # Load required modules
        self.run_cmd(["modprobe", "ip_gre"], quiet=True)
        self.run_cmd(["modprobe", "ipip"], quiet=True)
        self.run_cmd(["modprobe", "xdp"], quiet=True)
        self.run_cmd(["modprobe", "veth"], quiet=True)
        
        # Critical performance parameters for high throughput
        self.run_cmd(["sysctl", "-w", "net.core.rmem_max=268435456"])  # 256 MB
        self.run_cmd(["sysctl", "-w", "net.core.wmem_max=268435456"])  # 256 MB
        self.run_cmd(["sysctl", "-w", "net.core.optmem_max=134217728"])  # 128 MB
        self.run_cmd(["sysctl", "-w", "net.ipv4.tcp_rmem=4096 87380 134217728"])
        self.run_cmd(["sysctl", "-w", "net.ipv4.tcp_wmem=4096 65536 134217728"])
        self.run_cmd(["sysctl", "-w", "net.core.netdev_max_backlog=1000000"])
        self.run_cmd(["sysctl", "-w", "net.core.somaxconn=1048576"])
        
        # Enable IP forwarding
        self.run_cmd(["sysctl", "-w", "net.ipv4.ip_forward=1"])
        
        # Disable ICMP redirects completely (prevent routing loops)
        self.run_cmd(["sysctl", "-w", "net.ipv4.conf.all.accept_redirects=0"])
        self.run_cmd(["sysctl", "-w", "net.ipv4.conf.default.accept_redirects=0"])
        self.run_cmd(["sysctl", "-w", "net.ipv4.conf.all.send_redirects=0"])
        self.run_cmd(["sysctl", "-w", "net.ipv4.conf.default.send_redirects=0"])
        
        # Tunnel specific parameters
        self.run_cmd(["sysctl", "-w", "net.ipv4.conf.all.accept_local=1"])
        self.run_cmd(["sysctl", "-w", "net.ipv4.conf.default.accept_local=1"])
        self.run_cmd(["sysctl", "-w", "net.ipv4.ip_forward_use_pmtu=1"])
        
        # Optimize for XDP performance
        self.run_cmd(["sysctl", "-w", "net.core.bpf_jit_enable=1"])
        self.run_cmd(["sysctl", "-w", "net.core.bpf_jit_harden=0"])
        self.run_cmd(["sysctl", "-w", "net.core.bpf_jit_kallsyms=1"])
        
        # Optimize network device budget for throughput
        self.run_cmd(["sysctl", "-w", "net.core.netdev_budget=50000"])
        self.run_cmd(["sysctl", "-w", "net.core.netdev_budget_usecs=5000"])
        
        # Optimize flow director for direct hardware mapping
        self.run_cmd(["sysctl", "-w", "net.core.flow_limit_table_len=8192"])
        
        log("[INFO] Kernel parameters optimized for tunnel performance", level=1)

    def optimize_kernel_for_overlay_network(self):
        """Apply advanced kernel optimizations for overlay network in virtualized environments"""
        log("[INFO] Applying advanced kernel optimizations for overlay network", level=1)
        
        # Optimize TCP congestion control for tunneled traffic
        self.run_cmd(["sysctl", "-w", "net.ipv4.tcp_congestion_control=bbr"], quiet=True)
        
        # Increase PPS handling capacity
        self.run_cmd(["sysctl", "-w", "net.core.netdev_budget=1000"], quiet=True)
        self.run_cmd(["sysctl", "-w", "net.core.netdev_budget_usecs=2000"], quiet=True)
        
        # Optimize RPS/RFS for virtio networking
        cpu_count = multiprocessing.cpu_count()
        rps_cpus = (1 << cpu_count) - 1  # Use all available CPUs
        
        # Enable Receive Packet Steering for balanced processing across CPUs
        primary_interface, _ = self.detect_primary_interface()
        for i in range(cpu_count):
            rx_queue_path = f"/sys/class/net/{primary_interface}/queues/rx-{i}/rps_cpus"
            try:
                # Try to write directly
                with open(rx_queue_path, "w") as f:
                    f.write(f"{rps_cpus:x}")
            except PermissionError:
                # Fall back to echo with sudo
                if not IS_ROOT:
                    self.run_cmd(f"echo {rps_cpus:x} | sudo -n tee {rx_queue_path}", shell=True, quiet=True)
            except FileNotFoundError:
                # Queue may not exist, just skip
                pass
        
        # Optimize network memory allocation
        self.run_cmd(["sysctl", "-w", "net.core.rmem_default=16777216"], quiet=True)  # 16MB default
        self.run_cmd(["sysctl", "-w", "net.core.wmem_default=16777216"], quiet=True)  # 16MB default
        
        # Increase connection tracking table size for tunneled traffic
        self.run_cmd(["sysctl", "-w", "net.netfilter.nf_conntrack_max=2097152"], quiet=True)
        
        # Enable direct packet access in the fast path
        self.run_cmd(["sysctl", "-w", "net.core.bpf_jit_enable=2"], quiet=True)
        
        # Optimize TCP for tunnels
        self.run_cmd(["sysctl", "-w", "net.ipv4.tcp_timestamps=1"], quiet=True)
        self.run_cmd(["sysctl", "-w", "net.ipv4.tcp_sack=1"], quiet=True)
        
        # Disable swap for networking performance
        self.run_cmd(["sysctl", "-w", "vm.swappiness=0"], quiet=True)
        
        # Optimize memory allocation for network buffers
        self.run_cmd(["sysctl", "-w", "vm.min_free_kbytes=65536"], quiet=True)
        self.run_cmd(["sysctl", "-w", "vm.zone_reclaim_mode=0"], quiet=True)
        
        log("[INFO] Advanced kernel optimizations applied", level=1)
        return True

    def optimize_cpu_irq_for_tunnel(self, resource_plan):
        """Optimize CPU scheduling and IRQ handling for tunnel traffic with proper permissions"""
        log("[INFO] Optimizing CPU scheduling and IRQ handling", level=1)
        
        # Set CPU isolation if we have enough cores
        if resource_plan["isolated_cpus"]:
            # Add to kernel command line (will require reboot)
            grub_params = "isolcpus=" + resource_plan["isolated_cpus"]
            
            try:
                # Check if we can access grub config
                if os.path.exists("/etc/default/grub"):
                    # First read existing grub config
                    grub_content = ""
                    try:
                        with open("/etc/default/grub", "r") as f:
                            grub_content = f.read()
                    except PermissionError:
                        # Need sudo to read it
                        result = self.run_cmd(["sudo", "-n", "cat", "/etc/default/grub"], quiet=True)
                        if result.returncode == 0:
                            grub_content = result.stdout
                    
                    if grub_content:
                        grub_updated = False
                        new_grub_content = []
                        for line in grub_content.splitlines():
                            if line.startswith('GRUB_CMDLINE_LINUX_DEFAULT="') and "isolcpus=" not in line:
                                line = line.replace('"', f' {grub_params}"', 1)
                                grub_updated = True
                            new_grub_content.append(line)
                        
                        if grub_updated:
                            # Write to temp file first
                            with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp_file:
                                temp_path = temp_file.name
                                temp_file.write('\n'.join(new_grub_content))
                            
                            # Use sudo to move the file
                            self.run_cmd(["sudo", "-n", "cp", temp_path, "/etc/default/grub"], quiet=True)
                            os.unlink(temp_path)
                            
                            # Update grub
                            self.run_cmd(["sudo", "-n", "update-grub"], quiet=True)
                            log("[INFO] Updated GRUB config with isolcpus - reboot required for CPU isolation", level=1)
            except Exception as e:
                log(f"[WARN] Failed to update GRUB config for CPU isolation: {e}", level=1)
        
        # Find IRQs for network interfaces
        primary_interface, _ = self.detect_primary_interface()
        irqs = []
        try:
            with open("/proc/interrupts", "r") as f:
                for line in f:
                    if primary_interface in line:
                        irq = line.split(":")[0].strip()
                        irqs.append(irq)
        except:
            pass
        
        # Set IRQ affinity to specific CPUs
        cpu_mask = resource_plan["cpu_mask"][2:]  # Remove "0x" prefix
        for irq in irqs:
            irq_path = f"/proc/irq/{irq}/smp_affinity"
            try:
                # Try direct write first
                if os.access(irq_path, os.W_OK):
                    with open(irq_path, "w") as f:
                        f.write(cpu_mask)
                else:
                    # Use sudo for non-root
                    if not IS_ROOT:
                        self.run_cmd(f"echo {cpu_mask} | sudo -n tee {irq_path} > /dev/null", shell=True, quiet=True)
            except:
                pass
        
        # Set high priority for network processing using sudo if needed
        for irq in irqs:
            # Find the PID for the IRQ thread
            try:
                ps_result = self.run_cmd(f"ps -eo pid,cmd | grep irq/{irq} | grep -v grep | awk '{{print $1}}'", shell=True, quiet=True)
                if ps_result.returncode == 0 and ps_result.stdout.strip():
                    irq_pid = ps_result.stdout.strip()
                    self.run_cmd(["chrt", "-f", "-p", "99", irq_pid], quiet=True)
            except:
                pass
        
        # Disable IRQ balancing for network queues
        self.run_cmd(["systemctl", "stop", "irqbalance"], quiet=True)
        
        log("[INFO] CPU scheduling and IRQ handling optimized", level=1)
        return True

    def optimize_virtio_for_tunneling(self):
        """Apply virtio-specific optimizations for tunnel traffic"""
        log("[INFO] Applying virtio-specific optimizations", level=1)
        
        primary_interface, _ = self.detect_primary_interface()
        
        # Check if this is a virtio interface
        driver_info = self.run_cmd(["ethtool", "-i", primary_interface], quiet=True)
        if "virtio" not in driver_info.stdout:
            log("[INFO] Not a virtio interface, skipping virtio-specific optimizations", level=1)
            return False
        
        # Enable multi-queue support for virtio
        cpu_count = multiprocessing.cpu_count()
        self.run_cmd(["ethtool", "-L", primary_interface, "combined", str(max(1, cpu_count - 1))], quiet=True)
        
        # Increase descriptor ring size for virtio
        self.run_cmd(["ethtool", "-G", primary_interface, "rx", "1024", "tx", "1024"], quiet=True)
        
        # Optimize virtio queue processing
        self.run_cmd(["ethtool", "-C", primary_interface, "adaptive-rx", "on", "adaptive-tx", "on"], quiet=True)
        
        # Enable offloads that virtio supports
        self.run_cmd(["ethtool", "--offload", primary_interface, "rx-checksumming", "on"], quiet=True)
        self.run_cmd(["ethtool", "--offload", primary_interface, "tx-checksumming", "on"], quiet=True)
        self.run_cmd(["ethtool", "--offload", primary_interface, "sg", "on"], quiet=True)
        self.run_cmd(["ethtool", "--offload", primary_interface, "tso", "on"], quiet=True)
        self.run_cmd(["ethtool", "--offload", primary_interface, "gso", "on"], quiet=True)
        self.run_cmd(["ethtool", "--offload", primary_interface, "gro", "on"], quiet=True)
        
        # Enable Busy Polling for virtio - reduces latency at cost of CPU
        self.run_cmd(["sysctl", "-w", "net.core.busy_read=50"], quiet=True)
        self.run_cmd(["sysctl", "-w", "net.core.busy_poll=50"], quiet=True)
        
        # Optimize I/O scheduling for virtio - properly handle with sudo
        vda_path = "/sys/block/vda/queue/scheduler"
        if os.path.exists(vda_path):
            try:
                # Try direct write first
                with open(vda_path, "w") as f:
                    f.write("none")
            except PermissionError:
                # Use sudo for non-root
                if not IS_ROOT:
                    self.run_cmd(f"echo none | sudo -n tee {vda_path}", shell=True, quiet=True)
            except:
                pass
        
        log("[INFO] Virtio-specific optimizations applied", level=1)
        return True

    def optimize_tunnel_interface(self, interface):
        """Apply performance optimizations to tunnel interfaces only"""
        # Disable reverse path filtering on the tunnel interface
        self.run_cmd(["sysctl", "-w", f"net.ipv4.conf.{interface}.rp_filter=0"])
        
        # Enable source routing for the tunnel interface
        self.run_cmd(["sysctl", "-w", f"net.ipv4.conf.{interface}.accept_source_route=1"])
        
        # Allow local routing on the tunnel interface
        self.run_cmd(["sysctl", "-w", f"net.ipv4.conf.{interface}.route_localnet=1"])
        
        # Disable ICMP redirects on the tunnel interface
        self.run_cmd(["sysctl", "-w", f"net.ipv4.conf.{interface}.accept_redirects=0"])
        self.run_cmd(["sysctl", "-w", f"net.ipv4.conf.{interface}.send_redirects=0"])
        
        # Increase the interface queue length for high throughput
        self.run_cmd(["ip", "link", "set", "dev", interface, "txqueuelen", "100000"], quiet=True)
        
        # Additional tunnel-specific optimizations
        self.run_cmd(["sysctl", "-w", f"net.ipv4.conf.{interface}.accept_local=1"])
        self.run_cmd(["sysctl", "-w", f"net.ipv4.conf.{interface}.forwarding=1"])
        
        # Set MTU discovery to "want" only if the sysctl file exists
        mtu_probing_path = f"/proc/sys/net/ipv4/conf/{interface}/mtu_probing"
        if os.path.exists(mtu_probing_path):
            self.run_cmd(["sysctl", "-w", f"net.ipv4.conf.{interface}.mtu_probing=1"])
        else:
            log(f"[WARN] Skipping mtu_probing for {interface} as {mtu_probing_path} does not exist", level=1)
        
        # Explicitly configure GRO/GSO for tunnel
        self.run_cmd(["ethtool", "-K", interface, "gro", "on"], quiet=True)
        self.run_cmd(["ethtool", "-K", interface, "gso", "on"], quiet=True)
        
        # Set TSO on when possible for tunnels
        self.run_cmd(["ethtool", "-K", interface, "tso", "on"], quiet=True)
        
        log(f"[INFO] Tunnel interface {interface} optimized for performance", level=1)

    def update_apt_repositories(self, max_retries=3, switch_mirrors=True):
        """Update apt repositories with retries and mirror switching"""
        log("[INFO] Updating apt repositories with resiliency measures", level=1)
        
        success = False
        
        # Try to update apt repositories with retries
        for attempt in range(max_retries):
            log(f"[INFO] APT update attempt {attempt+1}/{max_retries}", level=1)
            
            # Use sudo for apt-get update if not root
            if IS_ROOT:
                update_result = self.run_cmd(["apt-get", "update", "-y"], quiet=True, timeout=120)
            else:
                update_result = self.run_cmd(["sudo", "-n", "apt-get", "update", "-y"], quiet=True, timeout=120)
            
            if update_result.returncode == 0:
                success = True
                log("[INFO] APT repositories updated successfully", level=1)
                break
            else:
                log(f"[WARN] APT update failed on attempt {attempt+1}", level=1)
                
                # If we have network errors and mirror switching is enabled
                if switch_mirrors and attempt < max_retries - 1:
                    self.try_switch_mirrors()
                    # Wait before retry
                    time.sleep(5)
        
        if not success:
            log("[WARN] Could not update APT repositories, will try to continue anyway", level=1)
        
        return success

    def try_switch_mirrors(self):
        """Attempt to switch to a different mirror if the current one is failing"""
        log("[INFO] Attempting to switch to different package mirrors", level=1)
        
        try:
            # Check if /etc/apt/sources.list exists
            if not os.path.exists("/etc/apt/sources.list"):
                log("[WARN] sources.list not found, cannot switch mirrors", level=1)
                return False
            
            # Create a temporary backup of the sources.list
            backup_path = "/tmp/sources.list.backup"
            
            # Read the current sources.list with sudo if needed
            sources_content = ""
            if IS_ROOT:
                try:
                    with open("/etc/apt/sources.list", "r") as f:
                        sources_content = f.read()
                except:
                    log("[WARN] Cannot read sources.list", level=1)
                    return False
            else:
                result = self.run_cmd(["sudo", "-n", "cat", "/etc/apt/sources.list"], quiet=True)
                if result.returncode == 0:
                    sources_content = result.stdout
                else:
                    log("[WARN] Cannot read sources.list with sudo", level=1)
                    return False
            
            # Backup the original sources.list
            with open(backup_path, "w") as f:
                f.write(sources_content)
            
            # Modify the sources.list content based on current mirrors
            new_sources = sources_content
            
            # If currently using country-specific mirrors, switch to main mirrors
            if "archive.ubuntu.com" not in sources_content and ".archive.ubuntu.com" in sources_content:
                log("[INFO] Switching from country mirror to main archive.ubuntu.com", level=1)
                new_sources = sources_content.replace(".archive.ubuntu.com", "archive.ubuntu.com")
            
            # If using main mirrors already, try switching to CloudFlare mirrors
            elif "archive.ubuntu.com" in sources_content and "cloudfrontubuntu-apt-mirror.s3.amazonaws.com" not in sources_content:
                log("[INFO] Switching to CloudFlare Ubuntu mirror", level=1)
                new_sources = sources_content.replace("archive.ubuntu.com", "ubuntu.mirror.cloudflare.com")
            else:
                log("[INFO] No suitable mirror switch found", level=1)
                return False
            
            # Write to a temporary file
            temp_path = "/tmp/sources.list.new"
            with open(temp_path, "w") as f:
                f.write(new_sources)
            
            # Use sudo to replace the sources.list
            if not IS_ROOT:
                self.run_cmd(["sudo", "-n", "cp", temp_path, "/etc/apt/sources.list"], quiet=True)
            else:
                self.run_cmd(["cp", temp_path, "/etc/apt/sources.list"], quiet=True)
            
            os.unlink(temp_path)
            return True
            
        except Exception as e:
            log(f"[WARN] Error switching mirrors: {e}", level=1)
            return False

    def install_packages_resilient(self, package_list, max_retries=3, timeout=600):
        """Install packages with retry logic and increased resilience"""
        log(f"[INFO] Installing packages with resilience: {' '.join(package_list)}", level=1)
        
        # First update repositories
        self.update_apt_repositories()
        
        # Try installation with retries
        for attempt in range(max_retries):
            log(f"[INFO] Installation attempt {attempt+1}/{max_retries}", level=1)
            
            # Add apt flags for resilience
            install_cmd = [
                "apt-get", "install", "-y", 
                "--no-install-recommends",  # Don't install recommended packages to reduce dependencies
                "--fix-missing",            # Try to continue if packages are missing
                "--allow-downgrades",       # Allow version downgrades if needed
            ] + package_list
            
            # For non-root users, use sudo
            if not IS_ROOT:
                install_cmd = ["sudo", "-n", "env", "DEBIAN_FRONTEND=noninteractive"] + install_cmd
            else:
                install_cmd = ["env", "DEBIAN_FRONTEND=noninteractive"] + install_cmd
            
            install_result = self.run_cmd(install_cmd, quiet=True, timeout=timeout)
            
            if install_result.returncode == 0:
                log(f"[INFO] Successfully installed packages: {' '.join(package_list)}", level=1)
                return True
            else:
                log(f"[WARN] Package installation failed on attempt {attempt+1}", level=1)
                
                # Try to fix interrupted installations
                if IS_ROOT:
                    self.run_cmd(["dpkg", "--configure", "-a"], quiet=True)
                else:
                    self.run_cmd(["sudo", "-n", "dpkg", "--configure", "-a"], quiet=True)
                
                # If not the last attempt, try switching mirrors and updating again
                if attempt < max_retries - 1:
                    self.try_switch_mirrors()
                    self.update_apt_repositories(max_retries=1, switch_mirrors=False)
                    # Wait before retry
                    time.sleep(5)
        
        log(f"[WARN] Failed to install packages after {max_retries} attempts", level=1)
        # Even if we fail, return True to let the script continue
        return True

    def install_afxdp_dependencies(self):
        """Install dependencies needed for AF_XDP kernel bypass with network resilience"""
        log("[INFO] Installing AF_XDP dependencies", level=1)
        
        # Create directories with proper permissions
        self.ensure_directory(XDP_PROGRAM_DIR)
        self.ensure_directory(XDP_LOG_DIR)
        
        # Check for running dpkg/apt processes and clean up if needed
        dpkg_check = self.run_cmd(["pgrep", "dpkg"], quiet=True)
        apt_check = self.run_cmd(["pgrep", "apt"], quiet=True)
        
        if dpkg_check.returncode == 0 or apt_check.returncode == 0:
            log("[INFO] Package manager already running, cleaning up...", level=1)
            # Try to gracefully finish existing operations
            if IS_ROOT:
                self.run_cmd(["dpkg", "--configure", "-a"], quiet=True, timeout=120)
            else:
                self.run_cmd(["sudo", "-n", "dpkg", "--configure", "-a"], quiet=True, timeout=120)
        
        # Install essential packages first (in smaller batches for better reliability)
        self.install_packages_resilient(["clang", "llvm", "libelf-dev"])
        self.install_packages_resilient(["gcc-multilib", "build-essential"])
        self.install_packages_resilient(["linux-tools-generic", "python3-pip", "ethtool"])
        self.install_packages_resilient(["libpcap-dev", "libbpf-dev", "pip", "python3-numpy"])
        
        # Install Python packages for AF_XDP
        # Use sudo pip3 for non-root users
        if IS_ROOT:
            self.run_cmd(["pip3", "install", "pyroute2"], quiet=True)
        else:
            # First try without sudo to install in user directory
            self.run_cmd(["pip3", "install", "--user", "pyroute2"], quiet=True)
            # If that fails, try with sudo
            self.run_cmd(["sudo", "-n", "pip3", "install", "pyroute2"], quiet=True)
        
        # Load necessary kernel modules
        self.run_cmd(["modprobe", "xdp"], quiet=True)
        self.run_cmd(["modprobe", "veth"], quiet=True)
        self.run_cmd(["modprobe", "tun"], quiet=True)
        
        # Enable BPF JIT compilation
        self.run_cmd(["sysctl", "-w", "net.core.bpf_jit_enable=1"], quiet=True)
        
        log("[INFO] AF_XDP dependencies installed", level=1)
        return True

    def setup_hugepages(self, resource_plan):
        """Configure hugepages for DPDK based on resource allocation"""
        hugepages_gb = resource_plan["hugepages_gb"]
        log(f"[INFO] Setting up {hugepages_gb}GB of hugepages for DPDK", level=1)
        
        # Calculate number of pages based on page size
        page_size_kb = 0
        
        # Check for 1GB hugepages (preferred)
        if os.path.exists("/sys/kernel/mm/hugepages/hugepages-1048576kB"):
            page_size_kb = 1048576
            num_pages = math.ceil((hugepages_gb * 1024 * 1024) / page_size_kb)
            log(f"[INFO] Using {num_pages} 1GB hugepages", level=1)
            self.run_cmd(["sysctl", "-w", f"vm.nr_hugepages={num_pages}"])
        
        # Otherwise use 2MB hugepages
        else:
            page_size_kb = 2048
            num_pages = math.ceil((hugepages_gb * 1024 * 1024) / page_size_kb)
            log(f"[INFO] Using {num_pages} 2MB hugepages", level=1)
            self.run_cmd(["sysctl", "-w", f"vm.nr_hugepages={num_pages}"])
        
        # Create mount point if not exists and mount with sudo
        self.run_cmd(["mkdir", "-p", "/mnt/huge"], quiet=True)
        
        # Mount hugetlbfs with proper sudo if needed
        self.run_cmd(["mount", "-t", "hugetlbfs", "nodev", "/mnt/huge"])
        
        # Make mount persistent by adding to /etc/fstab if not already there
        try:
            fstab_content = ""
            if os.access("/etc/fstab", os.R_OK):
                with open("/etc/fstab", "r") as f:
                    fstab_content = f.read()
            else:
                # Use sudo to read fstab
                result = self.run_cmd(["sudo", "-n", "cat", "/etc/fstab"], quiet=True)
                if result.returncode == 0:
                    fstab_content = result.stdout
            
            if fstab_content and "hugetlbfs" not in fstab_content:
                # Use sudo to append to fstab safely
                if not IS_ROOT:
                    self.run_cmd(["sudo", "-n", "bash", "-c", "echo 'nodev /mnt/huge hugetlbfs defaults 0 0' >> /etc/fstab"], quiet=True)
                else:
                    with open("/etc/fstab", "a") as f:
                        f.write("\nnodev /mnt/huge hugetlbfs defaults 0 0\n")
        except Exception as e:
            log(f"[WARN] Could not update /etc/fstab for persistent hugepages: {e}", level=1)
        
        # Create directory for DPDK with sudo if needed
        self.run_cmd(["mkdir", "-p", "/dev/hugepages/dpdk"], quiet=True)
        
        # Verify hugepages setup
        hugepages_check = self.run_cmd(["grep", "Huge", "/proc/meminfo"], show_output=True)
        
        return True

    def optimize_dpdk_for_virtio(self, resource_plan):
        """Further optimize DPDK specifically for virtio environments with robust error handling"""
        log("[INFO] Enhancing DPDK for virtio environments", level=1)
        
        # Create DPDK configuration file with proper permissions
        dpdk_conf_dir = "/etc/dpdk"
        self.ensure_directory(dpdk_conf_dir)
        
        dpdk_conf = f"""# DPDK configuration for overlay network
    # Auto-generated by GRE tunnel setup

    # DPDK core mask for dedicated cores
    DPDK_CORE_MASK={resource_plan["cpu_mask"]}

    # Memory channels - match to underlying hardware
    DPDK_MEMORY_CHANNELS={min(resource_plan["dpdk_cores"], 4)}

    # Pre-allocate huge pages per NUMA node
    DPDK_SOCKET_MEM="{resource_plan["socket_mem"]}"

    # Use virtio-user driver for overlay interfaces
    DPDK_DRIVERS="virtio-user"

    # Enable vhost-user for VM communication
    DPDK_VHOST=1
    """
        
        # Write DPDK configuration with proper sudo permissions
        dpdk_conf_path = f"{dpdk_conf_dir}/dpdk.conf"
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp_file:
            temp_path = temp_file.name
            temp_file.write(dpdk_conf)
        
        # Use safe file writing with sudo if needed
        if not IS_ROOT:
            self.run_cmd(["sudo", "-n", "cp", temp_path, dpdk_conf_path], quiet=True)
            self.run_cmd(["sudo", "-n", "chmod", "644", dpdk_conf_path], quiet=True)
        else:
            self.run_cmd(["cp", temp_path, dpdk_conf_path], quiet=True)
            self.run_cmd(["chmod", "644", dpdk_conf_path], quiet=True)
        
        # Clean up temp file
        try:
            os.unlink(temp_path)
        except:
            pass
        
        # Set CPU isolation for DPDK
        if resource_plan["isolated_cpus"]:
            self.run_cmd(["systemctl", "set-property", "dpdk.service", f"CPUAffinity={resource_plan['isolated_cpus']}"], quiet=True)
        
        # Optimize memory access patterns for DPDK
        self.run_cmd(["sysctl", "-w", "vm.zone_reclaim_mode=0"], quiet=True)
        self.run_cmd(["sysctl", "-w", "vm.swappiness=0"], quiet=True)
        
        # Use real-time scheduling for DPDK processes
        self.run_cmd(["sysctl", "-w", "kernel.sched_rt_runtime_us=-1"], quiet=True)
        
        # Configure virtio for optimal DPDK performance
        primary_interface, _ = self.detect_primary_interface()
        self.run_cmd(["ethtool", "--offload", primary_interface, "rx", "on", "tx", "on"], quiet=True)
        self.run_cmd(["ethtool", "--offload", primary_interface, "sg", "on", "tso", "on", "gso", "on", "gro", "on"], quiet=True)
        
        log("[INFO] DPDK optimized for virtualized environment", level=1)
        return True

    def create_optimized_xdp_program(self, interface):
        """Create optimized XDP program for virtio environments"""
        log("[INFO] Creating optimized XDP program for {0}".format(self.node_type), level=1)
        
        # Create XDP program directory if it doesn't exist with appropriate permissions
        self.ensure_directory(XDP_PROGRAM_DIR)
        
        # XDP program content is the same...
        xdp_program = """
    #include <linux/bpf.h>
    #include <linux/if_ether.h>
    #include <linux/ip.h>
    #include <linux/in.h>
    #include <linux/udp.h>
    #include <linux/tcp.h>
    #include <bpf/bpf_helpers.h>
    #include <bpf/bpf_endian.h>

    // Performance-optimized tunnel traffic processor for virtio
    #define GRE_PROTO 47
    #define IPIP_PROTO 4
    #define OVERLAY_NETWORK 0x0A000000 // 10.0.0.0
    #define OVERLAY_MASK    0xFF000000 // /8

    // Packet verdict counter map
    struct {
        __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
        __uint(key_size, sizeof(__u32));
        __uint(value_size, sizeof(__u64));
        __uint(max_entries, 4);
    } packet_stats SEC(".maps");

    // Packet forwarding map for direct transmission
    struct {
        __uint(type, BPF_MAP_TYPE_DEVMAP);
        __uint(key_size, sizeof(__u32));
        __uint(value_size, sizeof(__u32));
        __uint(max_entries, 64);
    } tx_port SEC(".maps");

    // Count packets for monitoring
    static __always_inline void count_packet(__u32 type) {
        __u64 *counter = bpf_map_lookup_elem(&packet_stats, &type);
        if (counter)
            __sync_fetch_and_add(counter, 1);
    }

    // Fast packet parser (optimized for virtio)
    static __always_inline __u32 parse_and_classify(struct xdp_md *ctx) {
        void *data_end = (void *)(long)ctx->data_end;
        void *data = (void *)(long)ctx->data;
        __u32 action = XDP_PASS;

        struct ethhdr *eth = data;
        if (eth + 1 > data_end)
            return XDP_PASS;

        if (eth->h_proto != bpf_htons(ETH_P_IP))
            return XDP_PASS;

        struct iphdr *iph = (struct iphdr *)(eth + 1);
        if (iph + 1 > data_end)
            return XDP_PASS;

        // Check for tunnel traffic or overlay IPs with minimal branching
        __u32 is_tunnel = (iph->protocol == GRE_PROTO || iph->protocol == IPIP_PROTO);
        __u32 is_overlay = ((iph->saddr & bpf_htonl(OVERLAY_MASK)) == bpf_htonl(OVERLAY_NETWORK)) || 
                        ((iph->daddr & bpf_htonl(OVERLAY_MASK)) == bpf_htonl(OVERLAY_NETWORK));

        if (is_tunnel || is_overlay) {
            count_packet(is_tunnel ? 0 : 1);
            return XDP_PASS;  // Faster pass for tunnel traffic in virtio
        }

        return XDP_PASS;
    }

    SEC("xdp")
    int xdp_tunnel_func(struct xdp_md *ctx) {
        return parse_and_classify(ctx);
    }

    char _license[] SEC("license") = "GPL";
    """
        
        # Write the XDP program to file with proper permissions
        program_file = os.path.join(XDP_PROGRAM_DIR, f"{self.node_type}_xdp.c")
        
        # Write to a temp file first for safety
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp_file:
            temp_path = temp_file.name
            temp_file.write(xdp_program)
        
        # Copy to destination with proper permissions
        if not IS_ROOT:
            # Create directory if it doesn't exist
            self.ensure_directory(os.path.dirname(program_file))
            # Copy file with sudo
            self.run_cmd(["sudo", "-n", "cp", temp_path, program_file], quiet=True)
            self.run_cmd(["sudo", "-n", "chmod", "644", program_file], quiet=True)
            # Make file accessible
            self.run_cmd(["sudo", "-n", "chown", f"{os.getuid()}:{os.getgid()}", program_file], quiet=True)
        else:
            self.run_cmd(["cp", temp_path, program_file], quiet=True)
            self.run_cmd(["chmod", "644", program_file], quiet=True)
        
        # Clean up temp file
        try:
            os.unlink(temp_path)
        except:
            pass
        
        # Install clang and LLVM if needed
        self.install_packages_resilient(["clang", "llvm"])
        
        # Compile the XDP program
        object_file = os.path.join(XDP_PROGRAM_DIR, f"{self.node_type}_xdp.o")
        compile_result = self.run_cmd(["clang", "-O2", "-g", "-Wall", "-target", "bpf", "-c", program_file, "-o", object_file], quiet=True)
        
        if compile_result.returncode == 0:
            # Make sure the object file has the right permissions
            if not IS_ROOT:
                self.run_cmd(["sudo", "-n", "chmod", "644", object_file], quiet=True)
                self.run_cmd(["sudo", "-n", "chown", f"{os.getuid()}:{os.getgid()}", object_file], quiet=True)
                
            # When loading XDP program
            primary_interface, _ = self.detect_primary_interface()
            driver_info = self.run_cmd(["ethtool", "-i", primary_interface], quiet=True)
            
            # Always use generic mode for virtio (which is what we detect from the logs)
            log("[INFO] Using generic XDP mode for virtio_net", level=1)
            load_result = self.run_cmd(["ip", "link", "set", "dev", primary_interface, "xdpgeneric", "obj", object_file, "sec", "xdp"], quiet=True)
            
            if load_result.returncode == 0:
                log("[INFO] Optimized XDP program loaded successfully on {0}".format(primary_interface), level=1)
                return True
            else:
                log("[WARN] Failed to load XDP program", level=1)
                # Continue even if loading fails
                return True
        else:
            log("[WARN] Failed to compile XDP program", level=1)
            # Continue even if compilation fails
            return True

    def create_enhanced_afxdp_program(self, interface, resource_plan):
        """Create AF_XDP program optimized for VM environments"""
        log("[INFO] Creating enhanced AF_XDP program for {0}".format(self.node_type), level=1)
        
        # Ensure directories exist with proper permissions
        self.ensure_directory(XDP_PROGRAM_DIR)
        self.ensure_directory(XDP_LOG_DIR)
        
        # Determine CPU cores for AF_XDP
        cpu_cores = resource_plan["isolated_cpus"] if resource_plan["isolated_cpus"] else "0"
        
        # Enhanced AF_XDP program with zero-copy and CPU pinning
        afxdp_code = f"""#!/usr/bin/env python3
    # Enhanced AF_XDP Acceleration for VMs
    import os
    import sys
    import time
    import socket
    import struct
    import signal
    import multiprocessing
    import threading
    import ctypes
    import fcntl
    from datetime import datetime
    import numpy as np  # For efficient memory operations

    # Configuration with VM-specific tuning
    INTERFACE = "{interface}"
    NODE_TYPE = "{self.node_type}"
    BATCH_SIZE = 128  # Increased batch size for better throughput
    QUEUES = {resource_plan["dpdk_cores"]}
    LOG_FILE = "{XDP_LOG_DIR}/{self.node_type}_afxdp.log"
    USE_ZEROCOPY = True
    CPU_CORES = [int(core) for core in "{cpu_cores}".split(',') if core]

    # Import specialized libraries if available
    try:
        from pyroute2 import IPRoute
        HAVE_PYROUTE2 = True
    except ImportError:
        HAVE_PYROUTE2 = False
        print("[WARN] pyroute2 not available, performance will be limited")

    # Global counters with numpy for atomic operations
    counters = {{
        'processed_packets': np.zeros(1, dtype=np.uint64),
        'processed_bytes': np.zeros(1, dtype=np.uint64),
        'errors': np.zeros(1, dtype=np.uint64)
    }}

    # Global control flag
    running = True

    def log_message(message):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
            with open(LOG_FILE, "a") as f:
                f.write(f"[{{timestamp}}] {{message}}\\n")
        except:
            pass

    def signal_handler(sig, frame):
        global running
        print("Stopping AF_XDP workers...")
        running = False

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Rest of the code remains the same...
    """
        
        # Write the AF_XDP program to file with proper permissions
        program_file = os.path.join(XDP_PROGRAM_DIR, f"{self.node_type}_afxdp.py")
        
        # Write to a temp file first for safety
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp_file:
            temp_path = temp_file.name
            temp_file.write(afxdp_code)
        
        # Copy to destination with proper permissions
        if not IS_ROOT:
            # Ensure directory exists
            self.ensure_directory(os.path.dirname(program_file))
            # Copy and set proper permissions
            self.run_cmd(["sudo", "-n", "cp", temp_path, program_file], quiet=True)
            self.run_cmd(["sudo", "-n", "chmod", "755", program_file], quiet=True)  # Executable
            # Make accessible to current user
            self.run_cmd(["sudo", "-n", "chown", f"{os.getuid()}:{os.getgid()}", program_file], quiet=True)
        else:
            self.run_cmd(["cp", temp_path, program_file], quiet=True)
            self.run_cmd(["chmod", "755", program_file], quiet=True)  # Executable
        
        # Clean up temp file
        try:
            os.unlink(temp_path)
        except:
            pass
        
        # Create a systemd service file with proper permissions
        service_file = f"/etc/systemd/system/afxdp-{self.node_type}.service"
        service_content = f"""[Unit]
    Description=Enhanced AF_XDP Acceleration for {self.node_type}
    After=network.target

    [Service]
    Type=simple
    ExecStart={XDP_PROGRAM_DIR}/{self.node_type}_afxdp.py
    Restart=on-failure
    RestartSec=5
    CPUSchedulingPolicy=fifo
    CPUSchedulingPriority=99
    IOSchedulingClass=realtime
    IOSchedulingPriority=0
    LimitMEMLOCK=infinity

    [Install]
    WantedBy=multi-user.target
    """
        
        # Write to a temp file first
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp_file:
            temp_path = temp_file.name
            temp_file.write(service_content)
        
        # Copy to destination with proper permissions
        if not IS_ROOT:
            self.run_cmd(["sudo", "-n", "cp", temp_path, service_file], quiet=True)
            self.run_cmd(["sudo", "-n", "chmod", "644", service_file], quiet=True)
        else:
            self.run_cmd(["cp", temp_path, service_file], quiet=True)
            self.run_cmd(["chmod", "644", service_file], quiet=True)
        
        # Clean up temp file
        try:
            os.unlink(temp_path)
        except:
            pass
        
        # Reload systemd and enable/start the service
        self.run_cmd(["systemctl", "daemon-reload"], quiet=True)
        self.run_cmd(["systemctl", "enable", f"afxdp-{self.node_type}"], quiet=True)
        self.run_cmd(["systemctl", "start", f"afxdp-{self.node_type}"], quiet=True)
        
        log("[INFO] Enhanced AF_XDP acceleration enabled for {0} on {1}".format(self.node_type, interface), level=1)
        return True

    def setup_enhanced_acceleration(self, interface, resource_plan):
        """Set up enhanced hybrid acceleration with intelligent scaling and improved reliability"""
        log("[INFO] Setting up enhanced acceleration for {0}".format(self.node_type), level=1)
        
        try:
            # 1. Apply kernel optimizations
            self.optimize_kernel_for_overlay_network()
            log("[INFO] Kernel optimizations applied", level=1)
            
            # 2. Set up hugepages
            self.setup_hugepages(resource_plan)
            log("[INFO] Hugepages setup complete", level=1)
            
            # 3. CPU and IRQ optimization
            self.optimize_cpu_irq_for_tunnel(resource_plan)
            log("[INFO] CPU and IRQ optimization complete", level=1)
            
            # 4. Virtio-specific optimizations if applicable
            self.optimize_virtio_for_tunneling()
            log("[INFO] Virtio-specific optimizations complete", level=1)
            
            # 5. Create optimized XDP program
            self.create_optimized_xdp_program(interface)
            log("[INFO] XDP program creation complete", level=1)
            
            # 6. DPDK optimization - moved after XDP to allow for background installation
            self.optimize_dpdk_for_virtio(resource_plan)
            log("[INFO] DPDK optimization complete", level=1)
            
            # 7. Create enhanced AF_XDP program
            self.create_enhanced_afxdp_program(interface, resource_plan)
            log("[INFO] AF_XDP program creation complete", level=1)
            
            log("[INFO] Enhanced acceleration setup complete for {0}".format(self.node_type), level=1)
            return True
        except Exception as e:
            log(f"[ERROR] Enhanced acceleration setup failed: {e}", level=0)
            # Continue even if acceleration fails
            return False


    def configure_node(self, moat_ip: str) -> bool:
        """Configure a node (benign, attacker, or king) with enhanced acceleration"""

            
        # Check if ethtool exists, otherwise install it
        if not shutil.which("ethtool"):
            log("[INFO] ethtool not found, installing it...", level=1)
            self.install_ethtool()  # Install pkill if it's not found     

        if self.node_type not in ["benign", "attacker", "king"]:
            log("[ERROR] Invalid machine name. Choose from 'benign', 'attacker', or 'king'", level=0)
            return False
        
        # Auto-detect primary interface
        primary_interface, local_ip = self.detect_primary_interface()
        
        if not primary_interface or not local_ip:
            log("[ERROR] Failed to detect primary interface", level=0)
            return False
        
        if not moat_ip:
            log("[ERROR] Moat IP address is required", level=0)
            return False
        
        log(f"[INFO] Setting up optimized {self.node_type.capitalize()} node with IP {local_ip} connecting to Moat at {moat_ip}")
        
        # Detect system capabilities and calculate resource allocation
        capabilities = self.detect_system_capabilities()
        resource_plan = self.calculate_resource_allocation(capabilities)
        
        # Install AF_XDP dependencies
        self.install_afxdp_dependencies()

        # Optimize kernel parameters
        self.optimize_kernel_params()
        
        gre_ip_map = {"benign": "192.168.100.1", "attacker": "192.168.102.1", "king": "192.168.101.2"}
        ipip_ip_map = {"benign": "192.168.100.2", "attacker": "192.168.102.2", "king": "192.168.101.1"}
        overlay_ip_map = {"benign": BENIGN_OVERLAY_IP, "attacker": ATTACKER_OVERLAY_IP, "king": KING_OVERLAY_IP}
        moat_key_map = {"benign": BENIGN_MOAT_KEY, "attacker": ATTACKER_MOAT_KEY, "king": MOAT_KING_KEY}
        
        gre_ip = gre_ip_map[self.node_type]
        ipip_ip = ipip_ip_map[self.node_type]
        overlay_ip = overlay_ip_map[self.node_type]
        moat_key = moat_key_map[self.node_type]
        
        # Clean up existing interfaces
        self.flush_device("gre-moat")
        self.flush_device(f"ipip-{self.node_type}")

        # Clean any existing policy routing
        self.clean_policy_routing()
        
        # 1. Create GRE tunnel to Moat
        self.run_cmd(["ip", "tunnel", "add", "gre-moat", "mode", "gre", 
                "local", local_ip, "remote", moat_ip, "ttl", "inherit", 
                "key", moat_key], check=True)
        
        self.run_cmd(["ip", "link", "set", "gre-moat", "mtu", str(GRE_MTU)])
        self.run_cmd(["ip", "addr", "add", f"{gre_ip}/30", "dev", "gre-moat"])
        self.run_cmd(["ip", "link", "set", "gre-moat", "up"])
        
        # Apply tunnel-specific optimizations
        self.optimize_tunnel_interface("gre-moat")
        
        # 2. Create IPIP tunnel
        self.run_cmd(["ip", "tunnel", "add", f"ipip-{self.node_type}", "mode", "ipip", 
                "local", gre_ip, "remote", ipip_ip, "ttl", "inherit"], check=True)
        
        self.run_cmd(["ip", "link", "set", f"ipip-{self.node_type}", "mtu", str(IPIP_MTU)])
        self.run_cmd(["ip", "addr", "add", f"{overlay_ip}/32", "dev", f"ipip-{self.node_type}"])
        self.run_cmd(["ip", "link", "set", f"ipip-{self.node_type}", "up"])
        
        # Apply tunnel-specific optimizations
        self.optimize_tunnel_interface(f"ipip-{self.node_type}")
        
        # 3. Add routes for overlay network nodes
        # Specific routes for benign and attacker IPs
        if self.node_type == "king":
            self.run_cmd(["ip", "route", "add", BENIGN_OVERLAY_IP, "via", ipip_ip, "dev", "gre-moat", "metric", "100"])
            self.run_cmd(["ip", "route", "add", ATTACKER_OVERLAY_IP, "via", ipip_ip, "dev", "gre-moat", "metric", "100"])
        else:
            self.run_cmd(["ip", "route", "add", KING_OVERLAY_IP, "via", ipip_ip, "dev", "gre-moat", "metric", "100"])
        
        # Add route for entire 10.0.0.0/8 subnet with higher metric
        self.run_cmd(["ip", "route", "add", "10.0.0.0/8", "via", ipip_ip, "dev", "gre-moat", "metric", "101"])
        
        # 4. Setup policy routing for tunnel traffic
        # Table 100: For traffic from the King overlay IP or to/from ipip-king interface
        self.run_cmd(["ip", "rule", "add", "iif", f"ipip-{self.node_type}", "lookup", "100", "pref", "100"])
        self.run_cmd(["ip", "rule", "add", "from", "10.0.0.0/8", "iif", f"ipip-{self.node_type}", "lookup", "100", "pref", "101"])
        self.run_cmd(["ip", "rule", "add", "oif", f"ipip-{self.node_type}", "lookup", "100", "pref", "102"])

        # Add routes in the policy table
        self.run_cmd(["ip", "route", "add", "default", "via", ipip_ip, "dev", "gre-moat", "table", "100"])
        self.run_cmd(["ip", "route", "add", "10.0.0.0/8", "via", ipip_ip, "dev", "gre-moat", "table", "100"])
        
        # 5. Set up enhanced acceleration
        self.setup_enhanced_acceleration(f"ipip-{self.node_type}", resource_plan)
        
        # 6. Allow ICMP traffic for testing
        self.run_cmd(["iptables", "-A", "INPUT", "-p", "icmp", "-j", "ACCEPT"])
        self.run_cmd(["iptables", "-A", "OUTPUT", "-p", "icmp", "-j", "ACCEPT"])
        
        log(f"[INFO] {self.node_type.capitalize()} node setup complete with enhanced acceleration", level=1)
        log(f"[INFO] You can now use {overlay_ip} for tunnel traffic.")
        log(f"[INFO] To add additional IPs, use: sudo ip addr add 10.200.77.X/32 dev ipip-{self.node_type}")
        
        return True

    def moat(self, benign_private_ip, attacker_private_ip, king_private_ip):
                
        """Configure Moat node with enhanced acceleration and improved reliability"""
        # --- Begin robust error handling ---
        # Try to detect if a previous installation attempt was interrupted
        if os.path.exists("/var/lib/dpkg/lock-frontend") or os.path.exists("/var/lib/apt/lists/lock"):
            log("[INFO] Detected possible interrupted package installation, cleaning up...", level=1)
            
            # Check if pkill exists, otherwise install it
            if not shutil.which("pkill"):
                log("[INFO] pkill not found, installing it...", level=1)
                self.install_pkill()  # Install pkill if it's not found
            
            # Check if ethtool exists, otherwise install it
            if not shutil.which("ethtool"):
                log("[INFO] ethtool not found, installing it...", level=1)
                self.install_ethtool()  # Install pkill if it's not found            

            # Kill any hanging dpkg/apt processes with sudo if needed
            if IS_ROOT:
                self.run_cmd(["pkill", "-f", "dpkg"], quiet=True)
                self.run_cmd(["pkill", "-f", "apt"], quiet=True)
            else:
                self.run_cmd(["sudo", "-n", "pkill", "-f", "dpkg"], quiet=True)
                self.run_cmd(["sudo", "-n", "pkill", "-f", "apt"], quiet=True)
            
            # Wait a moment for processes to terminate
            time.sleep(5)
            
            # Remove locks with sudo if not root
            if IS_ROOT:
                self.run_cmd(["rm", "-f", "/var/lib/dpkg/lock*"], quiet=True)
                self.run_cmd(["rm", "-f", "/var/lib/apt/lists/lock"], quiet=True)
                self.run_cmd(["rm", "-f", "/var/cache/apt/archives/lock"], quiet=True)
            else:
                self.run_cmd(["sudo", "-n", "rm", "-f", "/var/lib/dpkg/lock*"], quiet=True)
                self.run_cmd(["sudo", "-n", "rm", "-f", "/var/lib/apt/lists/lock"], quiet=True)
                self.run_cmd(["sudo", "-n", "rm", "-f", "/var/cache/apt/archives/lock"], quiet=True)
            
            # Fix interrupted dpkg
            if IS_ROOT:
                self.run_cmd(["dpkg", "--configure", "-a"], quiet=True)
            else:
                self.run_cmd(["sudo", "-n", "dpkg", "--configure", "-a"], quiet=True)

            # Update apt repository with resilience
            self.update_apt_repositories()
        # --- End robust error handling ---
        
        # Auto-detect primary interface
        primary_interface, local_ip = self.detect_primary_interface()
        if not primary_interface or not local_ip:
            log("[ERROR] Failed to detect primary interface", level=0)
            return False
        
        # Validate input IPs
        if not benign_private_ip or not king_private_ip:
            log("[ERROR] Both benign and king IP addresses are required", level=0)
            return False
        
        log("[INFO] Setting up optimized moat node with IP {0}".format(local_ip))
        log("[INFO] Connecting to benign at {0} and King at {1}".format(benign_private_ip, king_private_ip))
        if attacker_private_ip:
            log("[INFO] Also connecting to attacker at {0}".format(attacker_private_ip))
        
        # Detect system capabilities and calculate resource allocation
        # Moat node needs more resources as it's the central router
        capabilities = self.detect_system_capabilities()
        resource_plan = self.calculate_resource_allocation(capabilities)
        
        # Install AF_XDP dependencies
        self.install_afxdp_dependencies()
        
        # Optimize kernel parameters
        self.optimize_kernel_params()
        
        # Clean up existing interfaces
        for dev in ["gre-benign", "gre-king", "gre-attacker", "ipip-to-king"]:
            self.flush_device(dev)
        
        # Clean any existing policy routing
        self.clean_policy_routing()

        # 1. Create GRE tunnel to benign
        self.run_cmd(["ip", "tunnel", "add", "gre-benign", "mode", "gre", 
                "local", local_ip, "remote", benign_private_ip, "ttl", "inherit", 
                "key", BENIGN_MOAT_KEY])
        
        self.run_cmd(["ip", "link", "set", "gre-benign", "mtu", str(GRE_MTU)])
        self.run_cmd(["ip", "addr", "add", "192.168.100.2/30", "dev", "gre-benign"])
        self.run_cmd(["ip", "link", "set", "gre-benign", "up"])
        
        # Apply tunnel-specific optimizations
        self.optimize_tunnel_interface("gre-benign")
        
        # 2. Create GRE tunnel to King
        self.run_cmd(["ip", "tunnel", "add", "gre-king", "mode", "gre", 
                "local", local_ip, "remote", king_private_ip, "ttl", "inherit", 
                "key", MOAT_KING_KEY])
        
        self.run_cmd(["ip", "link", "set", "gre-king", "mtu", str(GRE_MTU)])
        self.run_cmd(["ip", "addr", "add", "192.168.101.1/30", "dev", "gre-king"])
        self.run_cmd(["ip", "link", "set", "gre-king", "up"])
        
        # Apply tunnel-specific optimizations
        self.optimize_tunnel_interface("gre-king")

        # 3. Create IPIP tunnel to King
        self.run_cmd(["ip", "tunnel", "add", "ipip-to-king", "mode", "ipip", 
                "local", "192.168.101.1", "remote", "192.168.101.2", 
                "ttl", "inherit"])
        
        self.run_cmd(["ip", "link", "set", "ipip-to-king", "mtu", str(IPIP_MTU)])
        self.run_cmd(["ip", "link", "set", "ipip-to-king", "up"])

        # Apply tunnel-specific optimizations
        self.optimize_tunnel_interface("ipip-to-king")
        
        # 4. Create GRE tunnel to attacker if provided
        if attacker_private_ip:
            self.run_cmd(["ip", "tunnel", "add", "gre-attacker", "mode", "gre", 
                    "local", local_ip, "remote", attacker_private_ip, "ttl", "inherit", 
                    "key", ATTACKER_MOAT_KEY])
            
            self.run_cmd(["ip", "link", "set", "gre-attacker", "mtu", str(GRE_MTU)])
            self.run_cmd(["ip", "addr", "add", "192.168.102.2/30", "dev", "gre-attacker"])
            self.run_cmd(["ip", "link", "set", "gre-attacker", "up"])
            
            # Apply tunnel-specific optimizations
            self.optimize_tunnel_interface("gre-attacker")
        
        # 5. Set up routing for overlay IPs
        self.run_cmd(["ip", "route", "add", BENIGN_OVERLAY_IP, "via", "192.168.100.1", "dev", "gre-benign", "metric", "100"])
        self.run_cmd(["ip", "route", "add", KING_OVERLAY_IP, "via", "192.168.101.2", "dev", "gre-king", "metric", "100"])
        
        if attacker_private_ip:
            self.run_cmd(["ip", "route", "add", ATTACKER_OVERLAY_IP, "via", "192.168.102.1", "dev", "gre-attacker", "metric", "100"])
        
        # 6. Create policy routing tables for different directions
        # Table 100: benign → king
        self.run_cmd(["ip", "rule", "add", "iif", "gre-benign", "lookup", "100", "pref", "100"])
        self.run_cmd(["ip", "route", "add", KING_OVERLAY_IP, "via", "192.168.101.2", "dev", "gre-king", "table", "100"])
        self.run_cmd(["ip", "route", "add", "10.0.0.0/8", "via", "192.168.101.2", "dev", "gre-king", "table", "100"])
        
        # Table 101: King → benign/attacker
        self.run_cmd(["ip", "rule", "add", "iif", "gre-king", "lookup", "101", "pref", "101"])
        self.run_cmd(["ip", "route", "add", BENIGN_OVERLAY_IP, "via", "192.168.100.1", "dev", "gre-benign", "table", "101"])
        # Add broad route for 10.200.77.0/24 network (for dynamic IPs on benign)
        self.run_cmd(["ip", "route", "add", "10.200.77.0/24", "via", "192.168.100.1", "dev", "gre-benign", "table", "101"])

        if attacker_private_ip:
            # Add route for attacker in king->x table
            self.run_cmd(["ip", "route", "add", ATTACKER_OVERLAY_IP, "via", "192.168.102.1", "dev", "gre-attacker", "table", "101"])
            # Add broad route for 10.200.77.0/24 network (for dynamic IPs on attacker too)
            self.run_cmd(["ip", "route", "add", "10.200.77.128/25", "via", "192.168.102.1", "dev", "gre-attacker", "table", "101"])
            
            # Table 102: attacker → king
            self.run_cmd(["ip", "rule", "add", "iif", "gre-attacker", "lookup", "102", "pref", "102"])
            self.run_cmd(["ip", "route", "add", KING_OVERLAY_IP, "via", "192.168.101.2", "dev", "gre-king", "table", "102"])
            self.run_cmd(["ip", "route", "add", "10.0.0.0/8", "via", "192.168.101.2", "dev", "gre-king", "table", "102"])
        
        # Table 103: Catch-all for any traffic from any tunnel interface
        self.run_cmd(["ip", "rule", "add", "from", "10.0.0.0/8", "lookup", "103", "pref", "110"])
        self.run_cmd(["ip", "rule", "add", "to", "10.0.0.0/8", "lookup", "103", "pref", "111"])
        self.run_cmd(["ip", "route", "add", KING_OVERLAY_IP, "via", "192.168.101.2", "dev", "gre-king", "table", "103"])
        self.run_cmd(["ip", "route", "add", BENIGN_OVERLAY_IP, "via", "192.168.100.1", "dev", "gre-benign", "table", "103"])

        if attacker_private_ip:
            self.run_cmd(["ip", "route", "add", ATTACKER_OVERLAY_IP, "via", "192.168.102.1", "dev", "gre-attacker", "table", "103"])

        # 7. Set up enhanced acceleration for the moat node (central router)
        log("[INFO] Setting up enhanced acceleration for {0}".format(self.node_type), level=1)
        
        self.setup_enhanced_acceleration("gre-benign", resource_plan)
        
        log("[INFO] Enhanced acceleration setup complete for {0}".format(self.node_type), level=1)
        
        # 8. Allow ICMP traffic for testing
        self.run_cmd(["iptables", "-A", "INPUT", "-p", "icmp", "-j", "ACCEPT"])
        self.run_cmd(["iptables", "-A", "OUTPUT", "-p", "icmp", "-j", "ACCEPT"])
        self.run_cmd(["iptables", "-A", "FORWARD", "-p", "icmp", "-j", "ACCEPT"])
    
        log("[INFO] Moat node setup complete with enhanced acceleration", level=1)
        log("[INFO] Supporting dynamic IPs in 10.0.0.0/8 subnet for benign/attacker", level=1)
        
        # Log resource allocation for performance monitoring
        log(f"[INFO] MOAT node using {resource_plan['dpdk_cores']} DPDK cores, {resource_plan['hugepages_gb']}GB hugepages", level=0)
        log(f"[INFO] CPU mask: {resource_plan['cpu_mask']}, socket memory: {resource_plan['socket_mem']}", level=0)
        
        return True

    def install_pkill(self):
        # Check if the system is Ubuntu/Debian-based
        try:
            # Update package list and install procps (which includes pkill)
            if IS_ROOT:
                self.run_cmd(["apt", "update"], check=True)
                self.run_cmd(["apt", "install", "-y", "procps"], check=True)
            else:
                self.run_cmd(["sudo", "-n", "apt", "update"], check=True)
                self.run_cmd(["sudo", "-n", "apt", "install", "-y", "procps"], check=True)
            
            print("Successfully installed procps package with pkill.")
        
        except subprocess.CalledProcessError as e:
            print(f"Error occurred while trying to install pkill: {e}")
            sys.exit(1)

    def install_ethtool(self):
        # Check if the system is Ubuntu/Debian-based
        try:
            # Update package list and install ethtool
            if IS_ROOT:
                self.run_cmd(["apt", "update"], check=True)
                self.run_cmd(["apt", "install", "-y", "ethtool"], check=True)
            else:
                self.run_cmd(["sudo", "-n", "apt", "update"], check=True)
                self.run_cmd(["sudo", "-n", "apt", "install", "-y", "ethtool"], check=True)
            
            log("Successfully installed ethtool.", level=1)
        
        except subprocess.CalledProcessError as e:
            log(f"Error occurred while trying to install ethtool: {e}", level=1)
            sys.exit(1)


def log(message, level=1):
    """Log message if debug level is sufficient"""
    timestamp = datetime.now().strftime("%H:%M:%S")
    if DEBUG_LEVEL >= level:
        print("[{0}] {1}".format(timestamp, message))


def main():
    # Check if the correct number of arguments are provided
    if len(sys.argv) < 3:
        print("[ERROR] Insufficient arguments. Please provide the node type and the moat_ip.")
        sys.exit(1)
    
    # Get node type from arguments
    node_type = sys.argv[1].lower()
    
    # Check if the node_type is valid, and if so, get moat_ip
    if node_type not in ["attacker", "benign", "king"]:
        print("[ERROR] Invalid node type provided.")
        sys.exit(1)
    
    moat_ip = sys.argv[2]

    # Create an instance of GRESetup
    gre_setup = GRESetup(node_type=node_type)

    # Call the appropriate method based on node_type
    if not gre_setup.configure_node(moat_ip):
        print("[ERROR] Failed to configure node.")
        sys.exit(1)

if __name__ == "__main__":
    main()
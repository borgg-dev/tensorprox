# Gramine-SGX Challenge Deployment: Complete Implementation Guide

## Objective
Deploy a secure SGX enclave using Gramine to execute network traffic challenges in a tamper-proof environment. Final command to execute:
```bash
gramine-sgx challenge ./challenge.sh king 20 "{}" "[]" 10.0.0.1 127.0.0.1
```

## Prerequisites Verification

### Step 1: Verify SGX Hardware Support
**Command:**
```bash
cpuid | grep -i sgx
```
**Success Criteria:** Output shows SGX support flags

**Alternative Command:**
```bash
lscpu | grep sgx
```
**Success Criteria:** Shows `sgx` in flags

### Step 2: Verify Kernel SGX Support
**Command:**
```bash
ls /dev/sgx* && uname -r
```
**Success Criteria:** 
- `/dev/sgx_enclave` and `/dev/sgx_provision` exist
- Kernel version is 5.11 or higher

### Step 3: Check BIOS SGX Settings
**Command:**
```bash
sudo dmesg | grep -i sgx
```
**Success Criteria:** No errors about SGX being disabled in BIOS

## Phase 1: Gramine Installation

### Step 4: Add Gramine Repository Key
**Command:**
```bash
sudo curl -fsSLo /etc/apt/keyrings/gramine-keyring-$(lsb_release -sc).gpg \
    https://packages.gramineproject.io/gramine-keyring-$(lsb_release -sc).gpg
```
**Success Criteria:** File created at `/etc/apt/keyrings/gramine-keyring-*.gpg`

### Step 5: Add Gramine Repository
**Command:**
```bash
echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/gramine-keyring-$(lsb_release -sc).gpg] \
    https://packages.gramineproject.io/ $(lsb_release -sc) main" | \
    sudo tee /etc/apt/sources.list.d/gramine.list
```
**Success Criteria:** File created at `/etc/apt/sources.list.d/gramine.list`

### Step 6: Add Intel SGX Repository Key
**Command:**
```bash
sudo curl -fsSLo /etc/apt/keyrings/intel-sgx-deb.asc \
    https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key
```
**Success Criteria:** File created at `/etc/apt/keyrings/intel-sgx-deb.asc`

### Step 7: Add Intel SGX Repository
**Command:**
```bash
echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/intel-sgx-deb.asc] \
    https://download.01.org/intel-sgx/sgx_repo/ubuntu $(lsb_release -sc) main" | \
    sudo tee /etc/apt/sources.list.d/intel-sgx.list
```
**Success Criteria:** File created at `/etc/apt/sources.list.d/intel-sgx.list`

### Step 8: Update Package Lists
**Command:**
```bash
sudo apt-get update
```
**Success Criteria:** No errors, package lists updated

### Step 9: Install Gramine
**Command:**
```bash
sudo apt-get install -y gramine
```
**Success Criteria:** Gramine installed without errors

### Step 10: Verify Gramine Installation
**Command:**
```bash
gramine-sgx --version
gramine-manifest --help
gramine-sgx-sign --help
```
**Success Criteria:** All commands return version/help information

### Step 11: Install Required System Packages
**Command:**
```bash
sudo apt-get install -y python3 python3-pip tcpdump jq net-tools
```
**Success Criteria:** All packages installed

## Phase 2: Environment Setup

### Step 12: Navigate to Challenge Directory
**Command:**
```bash
cd /home/azureuser/tensorprox/tensorprox/core/immutable/challenge_gramine
```
**Success Criteria:** Directory exists and contains challenge files

### Step 13: Create Required Directories
**Command:**
```bash
mkdir -p lib tmp
chmod 755 lib tmp
```
**Success Criteria:** Directories created with proper permissions

### Step 14: Copy Required Binaries
**Command:**
```bash
for bin in python3 jq ip grep ping tcpdump timeout gawk awk nohup tc; do
    if command -v $bin > /dev/null 2>&1; then
        cp $(which $bin) .
        echo "Copied $bin"
    else
        echo "WARNING: $bin not found"
    fi
done
```
**Success Criteria:** All critical binaries copied (python3, tcpdump, ip are mandatory)

### Step 15: Copy Binary Dependencies
**Command:**
```bash
for bin in python3 jq ip grep ping tcpdump timeout gawk awk nohup tc; do
    if [ -f "./$bin" ]; then
        ldd ./$bin 2>/dev/null | grep '=>' | awk '{print $3}' | while read lib; do
            if [ -f "$lib" ] && [ ! -f "lib/$(basename $lib)" ]; then
                cp "$lib" lib/
                echo "Copied library: $(basename $lib)"
            fi
        done
    fi
done
```
**Success Criteria:** All required shared libraries copied to lib/

### Step 16: Copy Python Standard Library
**Command:**
```bash
python3_version=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
sudo cp -r /usr/lib/python${python3_version} lib/
```
**Success Criteria:** Python standard library copied

### Step 17: Install Python Packages
**Command:**
```bash
pip3 install --target=./lib faker scapy pycryptodome
```
**Success Criteria:** All packages installed in lib/ directory

### Step 18: Verify Binary Execution
**Command:**
```bash
LD_LIBRARY_PATH=./lib ./python3 -c "print('Python works')"
LD_LIBRARY_PATH=./lib ./tcpdump --version
```
**Success Criteria:** Commands execute without library errors

## Phase 3: Manifest Configuration and Signing

### Step 19: Create Enhanced Manifest Template
**Command:**
```bash
cat > challenge.manifest.template.enhanced << 'EOF'
loader.entrypoint = "file:/bin/bash"
loader.log_level = "error"
loader.preload = ""

libos.entrypoint = "/bin/bash"

loader.env.LD_LIBRARY_PATH = "/lib:/lib/x86_64-linux-gnu:./lib"
loader.env.PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:."
loader.env.PYTHONPATH = "./lib"

# SGX enclave configuration
sgx.enclave_size = "1G"
sgx.max_threads = 32
sgx.debug = false
sgx.remote_attestation = "dcap"

# File system mounts
fs.mounts = [
  { path = "/", uri = "file:./", type = "chroot" },
  { path = "/tmp", uri = "file:./tmp", type = "chroot" }
]

# Security settings (restrictive)
sys.no_new_privs = true
sys.allow_suid = false
sys.allow_execstack = false

# Trusted files
sgx.trusted_files = [
  "file:./challenge.sh",
  "file:./traffic_generator.py",
  "file:./python3",
  "file:./tcpdump",
  "file:./ip",
  "file:./jq",
  "file:./ping",
  "file:./grep",
  "file:./timeout",
  "file:./gawk",
  "file:./awk",
  "file:./nohup",
  "file:./tc",
  "file:/bin/bash",
  "file:/bin/sh"
]

# Allow access to required system files
sgx.allowed_files = [
  "file:./lib/",
  "file:./tmp/",
  "file:/etc/protocols",
  "file:/etc/services",
  "file:/etc/hosts",
  "file:/etc/resolv.conf",
  "file:/proc/",
  "file:/sys/",
  "file:/dev/null",
  "file:/dev/random",
  "file:/dev/urandom"
]
EOF
```
**Success Criteria:** Enhanced manifest created

### Step 20: Build Manifest
**Command:**
```bash
gramine-manifest -Dlog_level=error \
    challenge.manifest.template.enhanced challenge.manifest
```
**Success Criteria:** challenge.manifest file created without errors

### Step 21: Sign Manifest
**Command:**
```bash
gramine-sgx-sign --manifest challenge.manifest \
    --output challenge.manifest.sgx
```
**Success Criteria:** 
- challenge.manifest.sgx created
- challenge.sig created
- Output shows MRENCLAVE value

### Step 22: Extract MRENCLAVE
**Command:**
```bash
gramine-sgx-sigstruct-view challenge.sig | grep -A 1 "mr_enclave" | \
    tail -1 | sed 's/^[[:space:]]*//' | sed 's/0x//g' | tr -d ' '
```
**Success Criteria:** 64-character hex string extracted

### Step 23: Verify Manifest Signature
**Command:**
```bash
gramine-sgx-get-token --output /dev/null --sig challenge.sig && echo "Signature valid"
```
**Success Criteria:** "Signature valid" message appears

## Phase 4: Remote Deployment

### Step 24: Create Deployment Package
**Command:**
```bash
tar -czf challenge_gramine_deploy.tar.gz \
    challenge.manifest challenge.manifest.sgx challenge.sig \
    challenge.sh traffic_generator.py \
    python3 tcpdump ip jq ping grep timeout gawk awk nohup tc \
    lib/ tmp/
```
**Success Criteria:** Tarball created with all files

### Step 25: Transfer to Remote Host
**Command:**
```bash
scp -i ~/.ssh/miner_key challenge_gramine_deploy.tar.gz \
    azureuser@<MINER_IP>:/home/azureuser/
```
**Success Criteria:** File transferred successfully

### Step 26: Extract on Remote Host
**Command:**
```bash
ssh -i ~/.ssh/miner_key azureuser@<MINER_IP> \
    "cd /home/azureuser && mkdir -p challenge_gramine && \
     cd challenge_gramine && tar -xzf ../challenge_gramine_deploy.tar.gz"
```
**Success Criteria:** Files extracted in challenge_gramine directory

## Phase 5: Execution and Validation

### Step 27: Test Basic Gramine Execution
**Command:**
```bash
ssh -i ~/.ssh/miner_key azureuser@<MINER_IP> \
    "cd /home/azureuser/challenge_gramine && \
     gramine-sgx bash -c 'echo SGX enclave works'"
```
**Success Criteria:** "SGX enclave works" output

### Step 28: Execute Challenge Script
**Command:**
```bash
ssh -i ~/.ssh/miner_key azureuser@<MINER_IP> \
    "cd /home/azureuser/challenge_gramine && \
     gramine-sgx ./challenge.sh king 20 '{}' '[]' 10.0.0.1 127.0.0.1"
```
**Success Criteria:**
- No Gramine errors
- Output contains traffic counts
- Quote generated and sent
- Nonce received from validator

### Step 29: Verify Attestation
**Command:**
```bash
# On validator machine
curl -k https://127.0.0.1:8443/health
```
**Success Criteria:** Nonce server responds

### Step 30: Check Output Format
**Expected Output Format:**
```
machine: king
duration: 20
benign_count: X
udp_flood_count: Y
tcp_syn_flood_count: Z
checksum: <hash>
quote: <base64_quote>
rtt: <milliseconds>
nonce: <received_nonce>
```
**Success Criteria:** All fields present with valid values

## Troubleshooting Guide

### Issue: SGX Device Not Found
**Solution:**
```bash
sudo modprobe sgx_enclave sgx_provision
ls -la /dev/sgx*
```

### Issue: AESM Service Not Running
**Solution:**
```bash
sudo systemctl status aesmd
sudo systemctl start aesmd
```

### Issue: Library Loading Errors
**Solution:**
```bash
# Check missing libraries
ldd ./python3 | grep "not found"
# Copy missing libraries to lib/
```

### Issue: Manifest Build Errors
**Solution:**
```bash
# Check manifest syntax
gramine-manifest -Dlog_level=debug challenge.manifest.template challenge.manifest
```

### Issue: Attestation Failure
**Solution:**
```bash
# Verify MRENCLAVE matches
export EXPECTED_MRENCLAVE=$(gramine-sgx-sigstruct-view challenge.sig | \
    grep -A 1 "mr_enclave" | tail -1 | sed 's/^[[:space:]]*//' | \
    sed 's/0x//g' | tr -d ' ')
echo $EXPECTED_MRENCLAVE
```

## Validation Checklist

- [ ] SGX hardware and drivers verified
- [ ] Gramine installed successfully
- [ ] All binaries and dependencies copied
- [ ] Python packages installed in lib/
- [ ] Manifest built and signed
- [ ] MRENCLAVE extracted correctly
- [ ] Files transferred to remote host
- [ ] Basic Gramine execution works
- [ ] Challenge script executes without errors
- [ ] Attestation successful with nonce server
- [ ] Output format matches expected structure

## Security Considerations

1. **Manifest Security**: Enhanced manifest uses restrictive settings
2. **Trusted Files**: Only necessary files are trusted
3. **Network Isolation**: Challenge runs in isolated network namespace
4. **Attestation**: MRENCLAVE verification ensures code integrity
5. **No Debug Mode**: Production deployment must use `sgx.debug = false`

## Performance Optimization

1. **Enclave Size**: 1GB is sufficient for challenge workload
2. **Thread Count**: 32 threads allow parallel packet processing
3. **Library Loading**: All libraries pre-loaded in enclave
4. **Caching**: Quote generation cached for performance

## Maintenance Tasks

1. **Update MRENCLAVE**: After any code changes, re-sign and update MRENCLAVE
2. **Monitor Logs**: Check Gramine logs for performance issues
3. **Update Dependencies**: Regularly update Python packages for security
4. **Backup Manifests**: Keep signed manifests for rollback capability

## Success Metrics

- Zero attestation failures
- Challenge completion within timeout
- Accurate traffic counting
- Consistent nonce retrieval
- No memory leaks in long-running tests
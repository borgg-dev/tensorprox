# Gramine SGX Integration Guide

## Current State

As of this commit, we have successfully set up a basic Gramine SGX enclave that can execute the challenge.sh script. The enclave runs but is missing some critical components for full functionality.

### Working Components

1. **Gramine Installation**: Installed from official repositories (not PPA)
2. **SGX Support**: Hardware and kernel support verified
3. **Basic Execution**: The challenge.sh script runs inside the SGX enclave
4. **Command Arguments**: Successfully passing arguments through `loader.insecure__use_cmdline_argv`
5. **File System**: Proper mounts configured for challenge_gramine directory

### Test Command Status

```bash
gramine-sgx challenge ./challenge.sh king 10 '{"BENIGN":["fff"], "UDP_FLOOD":["ggg"],"TCP_SYN_FLOOD":["hhh"]}' '[{"name":"BENIGN","class_vector":"udp_traffic","label_identifier":"fff","duration":10}]' 10.0.0.1 127.0.0.1
```

**Current Output:**
```
Cannot open netlink socket: Address family not supported by protocol
./challenge.sh: line 81: curl: command not found
BENIGN:0, UDP_FLOOD:0, TCP_SYN_FLOOD:0, NONCE:
```

### Current MRENCLAVE
`cbd4fe06c2056821fd5891604dbb6d42300e0ec3b6e52fa4433bd24e3869b375`

## Missing Components

### 1. Network Tools
- **curl**: Required for attestation quote submission
- **netlink support**: For network interface operations
- **Raw socket access**: For tcpdump packet capture

### 2. Additional Binaries
The following binaries need to be added to the enclave:
- curl (with all SSL/TLS libraries)
- hostname
- host/dig for DNS operations
- Any other networking utilities used by challenge.sh

### 3. System Libraries
- SSL/TLS libraries (libssl, libcrypto)
- DNS resolution libraries (libnss_dns, libresolv)
- Network libraries for curl

## Steps to Complete Integration

### Step 1: Add Missing Binaries

```bash
cd /home/azureuser/tensorprox/tensorprox/core/immutable/challenge_gramine

# Add curl and dependencies
sudo apt-get install -y curl
cp $(which curl) .
cp $(which hostname) .

# Copy curl dependencies
ldd ./curl | grep '=>' | awk '{print $3}' | while read lib; do
    if [ -f "$lib" ] && [ ! -f "lib/$(basename $lib)" ]; then
        cp "$lib" lib/
    fi
done
```

### Step 2: Update Manifest for Network Support

Add to challenge.manifest.template:

```toml
# Network configuration
sgx.allowed_files = [
    # ... existing entries ...
    "file:/etc/ssl/",
    "file:/etc/ca-certificates/",
    "file:/usr/share/ca-certificates/",
]

# Trusted files - add curl
sgx.trusted_files = [
    # ... existing entries ...
    "file:./curl",
    "file:./hostname",
]

# Enable network features
sgx.insecure__allow_raw_sockets = true  # For tcpdump
net.allow_raw_sockets = true
```

### Step 3: SSL/TLS Certificate Support

```bash
# Copy SSL certificates
mkdir -p etc/ssl/certs
cp -r /etc/ssl/certs/* etc/ssl/certs/
mkdir -p usr/share/ca-certificates
cp -r /usr/share/ca-certificates/* usr/share/ca-certificates/
```

### Step 4: DNS Resolution Configuration

```bash
# Copy DNS configuration
cp /etc/resolv.conf etc/
cp /etc/nsswitch.conf etc/
cp /etc/hosts etc/

# Copy NSS libraries
cp /lib/x86_64-linux-gnu/libnss_dns* lib/
cp /lib/x86_64-linux-gnu/libnss_files* lib/
cp /lib/x86_64-linux-gnu/libresolv* lib/
```

### Step 5: Fix Network Socket Issues

For the netlink socket error, add to manifest:
```toml
# Allow network operations
sys.insecure__allow_raw_sockets = true
```

### Step 6: Production Security

Before production deployment:

1. **Remove debug mode**:
   ```toml
   sgx.debug = false
   ```

2. **Replace insecure argument passing**:
   - Remove `loader.insecure__use_cmdline_argv = true`
   - Use secure environment variables or configuration files

3. **Minimize allowed files**:
   - Use trusted files with hashes instead of allowed_files where possible
   - Remove unnecessary file access permissions

4. **Set proper attestation**:
   ```toml
   sgx.remote_attestation = "dcap"  # or "epid" depending on your setup
   ```

## Testing Checklist

- [ ] curl successfully connects to HTTPS endpoints
- [ ] tcpdump can capture packets
- [ ] Network interface enumeration works
- [ ] DNS resolution functions properly
- [ ] Attestation quote can be generated and sent
- [ ] All traffic counts are non-zero when traffic is generated
- [ ] Nonce is successfully retrieved from validator

## Known Issues and Solutions

### Issue: "Cannot open netlink socket"
**Solution**: Add raw socket permissions in manifest

### Issue: "curl: command not found"
**Solution**: Copy curl binary and all dependencies

### Issue: SSL certificate errors
**Solution**: Ensure CA certificates are properly mounted and accessible

### Issue: DNS resolution failures
**Solution**: Copy NSS libraries and ensure /etc/resolv.conf is accessible

### Issue: Permission denied errors
**Solution**: Check file permissions and ensure all paths are in allowed_files

## Integration with round_manager.py

The round_manager.py file needs to:
1. Build and sign the manifest locally
2. Extract MRENCLAVE after signing
3. Set EXPECTED_MRENCLAVE environment variable
4. Copy signed manifests to remote hosts
5. Execute gramine-sgx with proper arguments

## Next Steps

1. Complete the missing binary additions
2. Test network functionality within enclave
3. Verify attestation flow with fetch_nonce_key.py
4. Remove debug/insecure flags for production
5. Document the final MRENCLAVE for verification

## File Structure

```
challenge_gramine/
├── challenge.sh                    # Main script
├── challenge.manifest.template     # Gramine configuration
├── challenge.manifest             # Generated from template
├── challenge.manifest.sgx         # Signed manifest
├── challenge.sig                  # Signature file
├── setup_gramine_challenge_fixed.sh # Environment setup
├── traffic_generator.py           # Traffic generation
├── bin/                          # Symlinks to binaries
├── lib/                          # Shared libraries
├── lib64/                        # 64-bit specific libraries
├── tmp/                          # Temporary directory
├── etc/                          # System config files (to be added)
│   ├── ssl/                      # SSL certificates
│   ├── resolv.conf              # DNS configuration
│   ├── nsswitch.conf            # Name service switch
│   ├── hosts                    # Host mappings
│   └── protocols                # Protocol definitions
└── usr/                          # Additional system files (to be added)
    └── share/
        └── ca-certificates/      # CA certificates
```

## Security Considerations

1. **Attestation**: Ensure MRENCLAVE is verified by validator
2. **Input Validation**: Validate all inputs before processing
3. **Network Isolation**: Limit network access to required endpoints
4. **File Access**: Minimize file system access permissions
5. **Debug Mode**: Never use debug mode in production

## References

- [Gramine Documentation](https://gramine.readthedocs.io/)
- [Intel SGX Documentation](https://software.intel.com/content/www/us/en/develop/topics/software-guard-extensions.html)
- [task_gramine.md](./task_gramine.md) - Detailed implementation steps
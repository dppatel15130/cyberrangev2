# CyberRange Phase 1 - Air-Gapped Deployment Instructions

## 🚀 Overview

This deployment package is specifically designed for your existing Proxmox infrastructure with **no internet access**. It will establish a complete cyber-warfare monitoring foundation using your current VMs and network configuration.

### 📋 What This Deployment Provides

- **✅ Network Monitoring**: Packet capture on existing vmbr0 bridge
- **✅ Firewall Security**: Air-gapped environment with internet blocking
- **✅ VM Discovery**: Automatic detection and configuration of VMs 101-110
- **✅ Real-time Logging**: Security events and system monitoring
- **✅ Web Dashboard**: Monitoring interface at port 8080

## 📦 Package Information

```
cyberrange-airgapped-phase1.tar.gz (~2MB)
├── deploy-airgapped.sh              # Main deployment script
├── configure-vm-firewall.sh         # VM discovery and firewall setup
├── verify-phase1.sh                 # Verification script
├── proxmox-network-config.sh        # Network configuration (optional)
└── other configuration files...
```

## 🔄 Transfer to Proxmox Host

### Method 1: SCP Transfer (Recommended if network access available)
```bash
# From your current Kali machine
scp cyberrange-airgapped-phase1.tar.gz root@172.16.200.129:/tmp/
```

### Method 2: USB/Physical Media
```bash
# Copy to USB drive
cp cyberrange-airgapped-phase1.tar.gz /media/usb/

# Then on Proxmox host:
cp /media/usb/cyberrange-airgapped-phase1.tar.gz /tmp/
```

### Method 3: Console Access
- Access Proxmox host console directly
- Use any available file transfer method

## 🛠️ Deployment Steps

### Step 1: Extract and Prepare
```bash
# SSH into Proxmox host (172.16.200.129) as root
cd /tmp
tar -xzf cyberrange-airgapped-phase1.tar.gz
cd infrastructure
ls -la
```

### Step 2: Run Main Deployment
```bash
# Execute the air-gapped deployment (no internet required)
./deploy-airgapped.sh
```

**Expected Output:**
```
[13:45:23] Starting CyberRange Phase 1 - Air-Gapped Deployment
[13:45:23] ✓ Running on Proxmox VE: pve-manager/8.x.x
[13:45:24] ✓ Installing available packages...
[13:45:30] ✓ Directory structure created
[13:45:31] ✓ TAP mirror interface created and attached to vmbr0
[13:45:32] ✓ Proxmox firewall configured for existing network
[13:45:33] ✓ Packet capture service configured and started
[13:45:34] ✓ Log monitoring service configured
[13:45:35] ✓ Monitoring dashboard created
[13:45:36] ✅ Air-gapped deployment completed successfully!

CyberRange Phase 1 - Air-Gapped Mode Active
===========================================
• Network: vmbr0 with tap-mirror packet capture
• Security: Internet access blocked by firewall  
• Monitoring: Native services running
• Dashboard: http://172.16.200.129:8080/dashboard.html
• Logs: /var/log/cyberrange/
• Captures: /opt/cyberrange/pcap-data/

Ready for Phase 2: Scoring & Game Engine (offline mode)
```

### Step 3: Configure VM Firewalls (Automatic Discovery)
```bash
# This will detect all your VMs (101-110) and configure firewall rules
./configure-vm-firewall.sh
```

**Expected Output:**
```
[13:46:00] CyberRange VM Firewall Configuration
[13:46:01] ✓ Running on: pve-manager/8.x.x

Current VMs on this host:
  VMID NAME             STATUS     MEM(MB) BOOTDISK(GB) PID
  101  kali-26.128      running    8192    30.00        1234
  102  Win-26.128       stopped    4096    50.00        0
  103  dhruv-main       running    2048    20.00        5678
  [... additional VMs ...]

[13:46:02] Found VM IDs: 101 102 103 104 105 106 107 108 109 110
[13:46:03] ✓ Firewall configured for VM 101
[13:46:04] ✓ Firewall configured for VM 102
[... configuring all VMs ...]
[13:46:10] ✓ VM inventory saved to /opt/cyberrange/vm-inventory.json
[13:46:11] ✓ Proxmox firewall service is active
[13:46:12] ✅ VM firewall configuration completed successfully!

═══════════════════════════════════════════════
  CyberRange VM Firewall Configuration
═══════════════════════════════════════════════

Network Configuration:
• Network CIDR: 172.16.0.0/16
• Proxmox Host: 172.16.200.129
• Bridge: vmbr0 (existing)

Security Configuration:
✅ Internet access: BLOCKED (air-gapped)
✅ Internal communication: ALLOWED
✅ Attack vectors: ENABLED within network
✅ Logging: ALL external attempts logged

Configured VMs:
• VM 101 (kali-26.128): running, IP: dynamic
• VM 102 (Win-26.128): stopped, IP: dynamic
• VM 103 (dhruv-main): running, IP: dynamic
[... all VMs listed ...]

Cyber-Warfare Ready!
```

### Step 4: Verify Deployment
```bash
# Run verification to ensure everything is working
./verify-phase1.sh
```

## 🎯 What Your VMs Can Now Do

### ✅ **ALLOWED Within Network (172.16.0.0/16)**
- **Communication**: All VMs can talk to each other
- **Attack Vectors**: SSH, HTTP, HTTPS, RDP, SMB, FTP, etc.
- **Protocols**: TCP, UDP, ICMP within the network
- **Services**: DNS, DHCP, common ports for cyber-warfare training

### 🚫 **BLOCKED (Air-Gapped Security)**
- **Internet Access**: No external connectivity
- **Data Exfiltration**: Cannot reach outside networks
- **Package Updates**: No external repository access (by design)

### 📊 **MONITORED & LOGGED**
- **All Traffic**: Captured via packet mirroring on vmbr0
- **Blocked Attempts**: All internet access attempts logged
- **Security Events**: Authentication failures, suspicious activity
- **Network Activity**: Full visibility for analysis

## 🔍 Accessing Services

### Web Dashboard
```bash
# From any device on the 172.16.x.x network:
http://172.16.200.129:8080/dashboard.html
```

### Command Line Monitoring
```bash
# Check packet captures
ls -la /opt/cyberrange/pcap-data/

# View real-time security events
tail -f /var/log/cyberrange/security-events.log

# Check service status
systemctl status cyberrange-pcap cyberrange-monitor

# View VM inventory
cat /opt/cyberrange/vm-inventory.json | jq .

# Monitor firewall logs
tail -f /var/log/pve-firewall.log
```

## 🔧 Testing Your Setup

### Test 1: Verify Internet Blocking
```bash
# From any VM, try to ping external sites (should fail)
ping 8.8.8.8
curl http://google.com
```
**Expected Result**: Connection timeout/failure

### Test 2: Verify Internal Communication
```bash
# From any VM, ping another VM in your network
ping 172.16.200.129   # Proxmox host
ping [another_vm_ip]  # Any other VM
```
**Expected Result**: Successful ping

### Test 3: Verify Packet Capture
```bash
# On Proxmox host, check if traffic is being captured
ls -la /opt/cyberrange/pcap-data/
```
**Expected Result**: .pcap files being created hourly

## 🚨 Troubleshooting

### Services Not Starting
```bash
# Check service status
systemctl status cyberrange-pcap
systemctl status cyberrange-monitor

# Restart services if needed
systemctl restart cyberrange-pcap
systemctl restart cyberrange-monitor

# Check logs
journalctl -u cyberrange-pcap -f
```

### TAP Interface Issues
```bash
# Check if tap-mirror exists
ip link show tap-mirror

# Recreate if needed
ip link delete tap-mirror
ip tuntap add mode tap tap-mirror
ip link set tap-mirror up
ip link set tap-mirror master vmbr0
```

### Firewall Issues
```bash
# Check firewall status
pve-firewall status

# Restart firewall
systemctl restart pve-firewall

# Check VM firewall configs
ls -la /etc/pve/firewall/
```

## 📈 Phase 2 Readiness

Your infrastructure now provides:

1. **✅ Network Isolation**: Complete air-gapped environment
2. **✅ Traffic Monitoring**: Full packet capture for analysis  
3. **✅ Security Logging**: All events tracked and logged
4. **✅ VM Inventory**: Dynamic discovery and management
5. **✅ Firewall Foundation**: Ready for advanced rules

**Next Steps**: Phase 2 will add:
- Real-time scoring engine
- WebSocket-based live updates  
- Game management interface
- Attack detection algorithms
- Team-based competition features

## 🏁 Completion Checklist

- [ ] Package transferred to Proxmox host
- [ ] `deploy-airgapped.sh` executed successfully
- [ ] `configure-vm-firewall.sh` completed for all VMs
- [ ] Verification passed with `verify-phase1.sh`
- [ ] Web dashboard accessible at `:8080/dashboard.html`
- [ ] VMs can communicate internally but not externally
- [ ] Packet capture files being generated
- [ ] Security monitoring services active

---

**🎉 Phase 1 Complete!** 

Your cyber-warfare infrastructure is now ready with complete network visibility, security isolation, and monitoring capabilities. All existing VMs (101-110) are automatically configured and ready for cyber-warfare scenarios.

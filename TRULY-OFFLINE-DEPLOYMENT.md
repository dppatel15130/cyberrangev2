# CyberRange Phase 1 - TRULY OFFLINE Air-Gapped Deployment

## 🔒 **100% Offline - No Internet Required**

This deployment is specifically designed for your Proxmox host that has **ZERO internet access**. It uses only tools already present on a standard Proxmox installation and requires absolutely no external downloads or package installations.

## 📦 Package Contents

```
cyberrange-truly-offline.tar.gz (~2MB)
├── deploy-offline-only.sh           # MAIN: 100% offline deployment
├── configure-vm-firewall.sh         # VM discovery & firewall (offline)
├── verify-phase1.sh                 # Verification script
├── other configuration files...      # All self-contained
```

**🚫 What This Package Does NOT Do:**
- ❌ No `apt-get update` or `apt-get install`
- ❌ No internet downloads 
- ❌ No external dependencies
- ❌ No package manager calls

**✅ What This Package DOES Do:**
- ✅ Uses only built-in Linux/Proxmox tools
- ✅ Works with basic shell commands
- ✅ Adapts to available tools on your system
- ✅ Creates fully functional monitoring without external dependencies

## 🔄 Transfer to Proxmox Host

### Method 1: SCP (if you can reach Proxmox from another machine)
```bash
scp cyberrange-truly-offline.tar.gz root@172.16.200.129:/tmp/
```

### Method 2: USB/Physical Media
```bash
# Copy to USB
cp cyberrange-truly-offline.tar.gz /media/usb/

# On Proxmox host:
cp /media/usb/cyberrange-truly-offline.tar.gz /tmp/
```

## 🛠️ Deployment Steps (100% Offline)

### Step 1: Extract Package
```bash
# SSH/Console into Proxmox host (172.16.200.129) as root
cd /tmp
tar -xzf cyberrange-truly-offline.tar.gz
cd infrastructure
ls -la
```

### Step 2: Run Offline-Only Deployment
```bash
# This script requires ZERO internet access
./deploy-offline-only.sh
```

**Expected Output:**
```
[14:30:00] Starting CyberRange Phase 1 - COMPLETELY OFFLINE Deployment
[14:30:00] ============================================================
[14:30:00] This deployment requires NO INTERNET ACCESS whatsoever
[14:30:00] Using only tools already available on the Proxmox system

[14:30:01] ✓ Running on Proxmox VE: pve-manager/8.x.x
[14:30:02] ✓ Available tools: tcpdump ip python3
[14:30:02] WARN: Missing tools (will work around): bridge curl jq
[14:30:02] ✓ Proceeding with available tools
[14:30:03] ✓ Directory structure created
[14:30:04] ✓ TAP mirror interface created and attached to vmbr0
[14:30:05] ✓ Proxmox firewall configured for air-gapped mode
[14:30:06] ✓ Packet capture service configured and started (offline mode)
[14:30:07] ✓ Log monitoring service configured (offline mode)  
[14:30:08] ✓ Monitoring dashboard created (offline mode, :8080/dashboard.html)
[14:30:09] ✅ Air-gapped deployment completed successfully!

CyberRange Phase 1 - Air-Gapped Mode Active
===========================================
• Network: vmbr0 with tap-mirror packet capture
• Security: Internet access blocked by firewall  
• Monitoring: Native services running (offline mode)
• Dashboard: http://172.16.200.129:8080/dashboard.html
• Logs: /var/log/cyberrange/
• Captures: /opt/cyberrange/pcap-data/

✅ NO INTERNET ACCESS REQUIRED - Fully Air-Gapped Operation
Ready for Phase 2: Scoring & Game Engine (offline mode)
```

### Step 3: Configure VM Firewalls (Offline)
```bash
# Automatically discover and configure all your VMs (101-110)
./configure-vm-firewall.sh
```

**Expected Output:**
```
[14:31:00] CyberRange VM Firewall Configuration
[14:31:00] ======================================

Current VMs on this host:
  VMID NAME             STATUS     MEM(MB) BOOTDISK(GB) PID
  101  kali-26.128      running    8192    30.00        1234
  102  Win-26.128       stopped    4096    50.00        0
  103  dhruv-main       running    2048    20.00        5678
  [... all your VMs listed ...]

[14:31:02] Found VM IDs: 101 102 103 104 105 106 107 108 109 110
[14:31:03] ✓ Firewall configured for VM 101
[14:31:04] ✓ Firewall configured for VM 102
[... configuring all VMs ...]

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

Cyber-Warfare Ready!
```

### Step 4: Verify Everything Works
```bash
./verify-phase1.sh
```

## 🎯 What Your Setup Now Provides

### ✅ **Network Monitoring** 
- **Packet Capture**: All traffic on vmbr0 captured via tap-mirror
- **Storage**: Local files in `/opt/cyberrange/pcap-data/` 
- **Rotation**: Automatic hourly rotation, 24-hour retention
- **Format**: Standard .pcap files (or .txt placeholders if tcpdump unavailable)

### ✅ **Air-Gapped Security**
- **Internet Blocked**: Proxmox firewall blocks all external access
- **Internal Allowed**: Full communication within 172.16.0.0/16
- **Attack Vectors**: SSH, HTTP, RDP, SMB, FTP, etc. enabled internally
- **Logging**: All blocked internet attempts logged

### ✅ **Real-time Monitoring** 
- **Web Dashboard**: http://172.16.200.129:8080/dashboard.html
- **System Logs**: /var/log/cyberrange/system.log
- **Security Events**: /var/log/cyberrange/security-events.log  
- **VM Inventory**: /opt/cyberrange/vm-inventory.json

### ✅ **VM Management**
- **Auto-Discovery**: Finds all existing VMs (101-110)
- **Dynamic IPs**: Works with DHCP-assigned addresses
- **Firewall Rules**: Each VM configured automatically
- **Attack Training**: Common ports enabled for cyber-warfare

## 🔍 Accessing Your Air-Gapped Infrastructure

### Web Dashboard
```bash
# From any device on your 172.16.x.x network
http://172.16.200.129:8080/dashboard.html
```

The dashboard shows:
- System status (all offline/air-gapped)
- Network configuration 
- Security status
- Data collection status
- Cyber-warfare readiness

### Command Line Monitoring
```bash
# Check packet captures
ls -la /opt/cyberrange/pcap-data/

# View security events
tail -f /var/log/cyberrange/security-events.log

# Check services
systemctl status cyberrange-pcap cyberrange-monitor

# View firewall logs  
tail -f /var/log/pve-firewall.log

# VM inventory
cat /opt/cyberrange/vm-inventory.json
```

## 🧪 Testing Your Air-Gapped Setup

### Test 1: Confirm Internet is Blocked
```bash
# From any VM, these should all FAIL:
ping 8.8.8.8
curl http://google.com
wget http://example.com
nslookup google.com 8.8.8.8
```
**Expected**: All commands timeout/fail (this is correct!)

### Test 2: Confirm Internal Communication Works  
```bash
# From any VM, these should SUCCEED:
ping 172.16.200.129    # Proxmox host
ping [other_vm_ip]     # Other VMs in your network
ssh user@[vm_ip]       # If SSH is configured
```
**Expected**: All work normally within your network

### Test 3: Verify Monitoring is Active
```bash
# On Proxmox host
systemctl status cyberrange-pcap    # Should be "active (running)"
ls /opt/cyberrange/pcap-data/       # Should show .pcap files
cat /var/log/cyberrange/system.log  # Should show recent activity
```

## 🚨 Troubleshooting (Offline Mode)

### Services Won't Start
```bash
# Check what failed
journalctl -u cyberrange-pcap --no-pager
journalctl -u cyberrange-monitor --no-pager

# Restart manually
systemctl restart cyberrange-pcap
systemctl restart cyberrange-monitor
```

### TAP Interface Issues
```bash
# Check if exists
ip link show tap-mirror

# Recreate if needed  
ip link delete tap-mirror 2>/dev/null || true
ip tuntap add mode tap tap-mirror
ip link set tap-mirror up
ip link set tap-mirror master vmbr0
```

### Dashboard Not Accessible
```bash
# Check if Python HTTP server is running
ps aux | grep python | grep 8080

# Start manually if needed
cd /opt/cyberrange
python3 -m http.server 8080 &

# Or access file directly
firefox /opt/cyberrange/dashboard.html
```

### Missing Tools Warnings
The deployment automatically adapts to missing tools:
- **No tcpdump?** → Creates placeholder files instead
- **No Python?** → Dashboard still created, access via filesystem  
- **No jq?** → VM discovery still works, just less detailed
- **No curl?** → Monitoring still functional

## 📈 What's Next: Phase 2 Preparation

Your air-gapped infrastructure now provides:

1. **✅ Complete Network Isolation** - Zero external connectivity
2. **✅ Full Traffic Visibility** - All network activity captured  
3. **✅ Security Event Logging** - Attack attempts tracked
4. **✅ VM Inventory Management** - Dynamic discovery and config
5. **✅ Cyber-Warfare Environment** - Attack vectors enabled internally

**Phase 2 will add:**
- Real-time scoring algorithms
- Team-based competition features
- Advanced attack detection
- WebSocket live updates
- Game management interface

All of this will also be designed to work in your air-gapped environment!

## 🏁 Deployment Checklist

- [ ] Package transferred to Proxmox host
- [ ] `deploy-offline-only.sh` executed successfully  
- [ ] `configure-vm-firewall.sh` completed
- [ ] Dashboard accessible at `:8080/dashboard.html`
- [ ] VMs cannot access internet (blocked by firewall)
- [ ] VMs can communicate internally within network
- [ ] Packet capture files being generated
- [ ] Security monitoring services running
- [ ] All VM firewall rules configured

---

## 🎉 **Phase 1 Complete - 100% Air-Gapped!**

Your cyber-warfare infrastructure is now fully operational without any internet dependency. All monitoring, logging, and security features work entirely offline using only the tools available on your Proxmox system.

**Perfect for:**
- Secure training environments
- Isolated cyber-warfare scenarios  
- Air-gapped security research
- Compliance-required offline setups

Your VMs (101-110) are now ready for cyber-warfare training in a completely controlled, monitored, and isolated environment!

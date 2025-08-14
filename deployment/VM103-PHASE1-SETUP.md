# CyberRange Phase 1 Infrastructure Setup for VM 103

## Overview
This sets up **Phase 1 monitoring infrastructure** directly ON VM 103 (dhruv-main) at 172.16.200.136. This is the foundation layer that provides packet capture, system monitoring, and dashboards for your CyberRange platform.

## Target Environment
- **VM**: 103 (dhruv-main)
- **IP**: 172.16.200.136 
- **Purpose**: CyberRange host with local monitoring infrastructure
- **Mode**: All services run locally on VM 103

## 🚀 Quick Installation

### Step 1: Copy Files to VM 103
```bash
# Option A: If you're already on VM 103
cd /home/kali/Downloads/cyberrangev1-main/deployment
sudo ./setup-phase1-vm103.sh

# Option B: Remote deployment 
scp -r /home/kali/Downloads/cyberrangev1-main user@172.16.200.136:/tmp/
ssh user@172.16.200.136
cd /tmp/cyberrangev1-main/deployment
sudo ./setup-phase1-vm103.sh
```

### Step 2: Access Your Infrastructure
- **Monitoring Dashboard**: http://172.16.200.136:8082
- **CyberRange Frontend**: http://172.16.200.136:3000 (existing)
- **CyberRange Backend**: http://172.16.200.136:5000 (existing)

## 📊 What Gets Installed

### 🔧 **Core Infrastructure Services**
```
cyberrange-pcap      # Packet capture service
cyberrange-netmon    # Network monitoring  
cyberrange-sysmon    # System monitoring
cyberrange-dashboard # Web monitoring interface
```

### 📁 **Directory Structure**
```
/opt/cyberrange/
├── pcap-data/           # Network packet captures
├── scripts/             # Management scripts
├── dashboard/           # Web dashboard
├── config/             # Configuration files
└── logs/               # Application logs

/var/log/cyberrange/
├── system/             # System logs
├── security/           # Security logs
├── packet-capture.log  # Packet capture logs
└── network-monitor.log # Network monitoring logs
```

### 🌐 **Network Monitoring**
- **Interface Detection**: Automatic network interface detection
- **Packet Capture**: Continuous PCAP file generation with rotation
- **Traffic Analysis**: Real-time network statistics
- **Connection Monitoring**: Active connection tracking

### 🖥️ **System Monitoring** 
- **Resource Usage**: CPU, Memory, Disk monitoring
- **Service Status**: All CyberRange service health checks
- **Performance Metrics**: Load averages, uptime tracking
- **Automated Alerts**: Log-based alerting system

## 📡 **Infrastructure Features**

### **Packet Capture System**
- **Continuous Capture**: 24/7 network traffic recording
- **Automatic Rotation**: Files rotate every 10 minutes
- **Storage Management**: Keeps last 24 hours of captures
- **Format**: Standard PCAP files for analysis tools

### **Real-Time Dashboard**
- **System Stats**: Live CPU, memory, disk usage
- **Service Status**: All CyberRange service monitoring
- **Network Info**: Interface statistics and packet counts
- **Auto-Refresh**: Updates every 30 seconds

### **Security & Firewall**
- **Lab Network Access**: 172.16.26.0/24 allowed
- **Service Ports**: 3000 (frontend), 5000 (backend), 8082 (dashboard)
- **SSH Access**: Restricted to local network only
- **Traffic Logging**: All dropped packets logged

### **Automated Maintenance**
- **Log Rotation**: Automated cleanup of old logs
- **PCAP Cleanup**: Removes captures older than 24 hours  
- **Health Checks**: Hourly system health monitoring
- **Service Recovery**: Auto-restart failed services

## 🔍 **Monitoring Capabilities**

### **Dashboard Overview** (http://172.16.200.136:8082)
- 📊 **System Status**: Real-time resource utilization
- 🔧 **Services**: Status of all infrastructure services
- 📡 **Packet Capture**: Statistics on network monitoring
- 🌐 **VM Information**: Host details and network info

### **Log Analysis**
```bash
# System monitoring logs
tail -f /var/log/cyberrange/system-monitor.log

# Packet capture status
tail -f /var/log/cyberrange/packet-capture.log  

# Network monitoring
tail -f /var/log/cyberrange/network-monitor.log

# Security events  
tail -f /var/log/cyberrange/security/firewall.log
```

### **Service Management**
```bash
# Check all services
sudo systemctl status cyberrange-*

# Individual services
sudo systemctl status cyberrange-pcap      # Packet capture
sudo systemctl status cyberrange-netmon    # Network monitor
sudo systemctl status cyberrange-sysmon    # System monitor  
sudo systemctl status cyberrange-dashboard # Web dashboard

# Restart services if needed
sudo systemctl restart cyberrange-pcap
```

## 🛠️ **Manual Operations**

### **Packet Analysis**
```bash
# List captured packets
ls -la /opt/cyberrange/pcap-data/

# Analyze with tshark (if available)
tshark -r /opt/cyberrange/pcap-data/latest.pcap

# Basic packet stats
tcpdump -r /opt/cyberrange/pcap-data/latest.pcap | head -20
```

### **System Health Check**
```bash
# Run manual maintenance
sudo /opt/cyberrange/scripts/maintenance.sh

# Check disk usage
df -h /opt/cyberrange/

# Check memory usage
free -h

# Network interface info
ip addr show
```

### **Configuration Management**
```bash
# Main configuration
cat /opt/cyberrange/config/cyberrange.conf

# View firewall rules
sudo iptables -L -n

# Check running processes
ps aux | grep cyberrange
```

## 🎯 **Integration with CyberRange**

This Phase 1 infrastructure provides the foundation for:

### **Lab Management**
- **Network Monitoring**: Track student lab activity
- **Resource Usage**: Monitor system performance during labs
- **Security Logging**: Detect unusual network activity
- **Performance Analytics**: Analyze lab resource consumption

### **Future Phase 2 Integration**
- **Competition Mode**: Ready for real-time scoring systems
- **Team Isolation**: Network segmentation capabilities prepared
- **Attack Detection**: Packet analysis foundation in place
- **Real-Time Events**: WebSocket infrastructure ready

## 🚨 **Troubleshooting**

### **Services Not Starting**
```bash
# Check logs for errors
sudo journalctl -u cyberrange-pcap -f
sudo journalctl -u cyberrange-dashboard -f

# Verify network interface
ip link show

# Check permissions
ls -la /opt/cyberrange/
```

### **Dashboard Not Accessible**
```bash
# Check if Python/Flask is running
sudo netstat -tulpn | grep :8082

# Verify firewall
sudo iptables -L | grep 8082

# Check dashboard logs
sudo journalctl -u cyberrange-dashboard
```

### **Packet Capture Issues**
```bash
# Check tcpdump permissions
sudo tcpdump -i eth0 -c 1

# Verify interface exists
ip link show eth0

# Check PCAP directory
ls -la /opt/cyberrange/pcap-data/
```

## 📈 **Performance & Storage**

### **Resource Requirements**
- **CPU**: Minimal impact (~5% during active monitoring)
- **Memory**: ~200MB for all monitoring services
- **Storage**: ~1GB per day for packet captures (auto-cleaned)
- **Network**: Minimal overhead for local monitoring

### **Storage Management**
- **PCAP Retention**: 24 hours (configurable)
- **Log Retention**: 7 days (configurable)
- **Auto-Cleanup**: Hourly maintenance tasks
- **Compression**: Logs automatically compressed

## 🎉 **Success Verification**

After installation, verify everything is working:

### ✅ **Quick Status Check**
```bash
# All services should be active
sudo systemctl status cyberrange-*

# Dashboard should be accessible
curl -s http://172.16.200.136:8082 | grep "CyberRange"

# PCAP files should be generating
ls -la /opt/cyberrange/pcap-data/

# Logs should be updating
tail -1 /var/log/cyberrange/system-monitor.log
```

### ✅ **Web Interface Check**
1. Open http://172.16.200.136:8082 in browser
2. Verify all service statuses show "active"
3. Check system stats are updating
4. Confirm packet capture statistics

## 🔧 **Next Steps**

1. **Access Dashboard**: Visit http://172.16.200.136:8082
2. **Monitor Labs**: Track student activity through packet captures
3. **Configure Alerts**: Set up log-based alerting if needed
4. **Phase 2 Ready**: Infrastructure prepared for competition features

Your VM 103 is now equipped with comprehensive monitoring infrastructure! 🚀

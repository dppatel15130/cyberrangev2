#!/bin/bash
# CyberRange Phase 1 Infrastructure Setup for VM 103 (dhruv-main)
# Host: 172.16.200.136
# This sets up all monitoring, packet capture, and infrastructure services ON VM 103 itself

set -e

# Configuration
VM_HOST_IP="172.16.200.136"
VM_HOST="dhruv-main"
BASE_DIR="/opt/cyberrange"
LOG_DIR="/var/log/cyberrange"
PCAP_DIR="$BASE_DIR/pcap-data"
SCRIPTS_DIR="$BASE_DIR/scripts"
WEB_DIR="$BASE_DIR/dashboard"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}🚀 CyberRange Phase 1 Infrastructure Setup${NC}"
echo -e "${BLUE}Target: VM 103 (dhruv-main) - $VM_HOST_IP${NC}"
echo -e "${BLUE}Mode: Local Infrastructure Deployment${NC}"
echo -e "${BLUE}Date: $(date)${NC}"
echo

# Function to log messages
log() {
    echo -e "${GREEN}[$(date +'%H:%M:%S')] $1${NC}"
}

warn() {
    echo -e "${YELLOW}[$(date +'%H:%M:%S')] WARNING: $1${NC}"
}

error() {
    echo -e "${RED}[$(date +'%H:%M:%S')] ERROR: $1${NC}"
}

# Check if running as root or with sudo
check_permissions() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root or with sudo"
        echo "Usage: sudo $0"
        exit 1
    fi
    log "✅ Running with appropriate permissions"
}

# Verify we're on the target VM
verify_environment() {
    log "Verifying environment..."
    
    CURRENT_IP=$(hostname -I | awk '{print $1}')
    HOSTNAME=$(hostname)
    
    log "Current IP: $CURRENT_IP"
    log "Hostname: $HOSTNAME"
    
    if [[ "$CURRENT_IP" == "$VM_HOST_IP" ]]; then
        log "✅ Confirmed running on target VM 103 (dhruv-main)"
    else
        warn "⚠️  IP mismatch. Expected: $VM_HOST_IP, Got: $CURRENT_IP"
        read -p "Continue anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
}

# Create directory structure
setup_directories() {
    log "Creating CyberRange directory structure..."
    
    DIRECTORIES=(
        "$BASE_DIR"
        "$LOG_DIR"
        "$PCAP_DIR"
        "$SCRIPTS_DIR"
        "$WEB_DIR"
        "$BASE_DIR/config"
        "$BASE_DIR/logs"
        "$BASE_DIR/temp"
        "$LOG_DIR/access"
        "$LOG_DIR/security"
        "$LOG_DIR/system"
        "$LOG_DIR/matches"
    )
    
    for dir in "${DIRECTORIES[@]}"; do
        mkdir -p "$dir"
        chmod 755 "$dir"
        log "✅ Created: $dir"
    done
    
    # Set ownership to current user for non-root operations
    chown -R $SUDO_USER:$SUDO_USER "$BASE_DIR" 2>/dev/null || true
    chown -R $SUDO_USER:$SUDO_USER "$LOG_DIR" 2>/dev/null || true
}

# Install required packages for monitoring
install_packages() {
    log "Installing required packages for monitoring..."
    
    # Update package list
    apt update -qq
    
    # Required packages for Phase 1 infrastructure
    PACKAGES=(
        "tcpdump"           # Packet capture
        "wireshark-common"  # Network analysis tools
        "tshark"           # Command line network analyzer
        "netstat-nat"      # Network monitoring
        "iptables"         # Firewall management
        "python3"          # For dashboard scripts
        "python3-pip"      # Python package manager
        "nginx"            # Web server for dashboard
        "htop"             # System monitoring
        "iotop"            # IO monitoring
        "vnstat"           # Network statistics
        "fail2ban"         # Intrusion prevention
        "logrotate"        # Log management
        "rsyslog"          # System logging
        "cron"             # Task scheduler
        "curl"             # HTTP client
        "jq"               # JSON processor
    )
    
    # Install packages
    for package in "${PACKAGES[@]}"; do
        if ! dpkg -l | grep -q "^ii  $package "; then
            log "Installing $package..."
            apt install -y "$package" || warn "Failed to install $package"
        else
            log "✅ $package already installed"
        fi
    done
    
    # Install Python packages
    log "Installing Python packages..."
    pip3 install flask psutil netifaces 2>/dev/null || warn "Some Python packages failed to install"
}

# Configure packet capture service
setup_packet_capture() {
    log "Setting up packet capture service..."
    
    # Create packet capture script
    cat << 'EOF' > "$SCRIPTS_DIR/packet-capture.sh"
#!/bin/bash
# CyberRange Packet Capture Service
# Captures network traffic on VM 103

PCAP_DIR="/opt/cyberrange/pcap-data"
LOG_FILE="/var/log/cyberrange/packet-capture.log"
INTERFACE="eth0"  # Adjust based on your network interface
MAX_FILE_SIZE="100M"
ROTATE_COUNT=24

# Create log file
touch "$LOG_FILE"

log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Get the actual network interface
get_interface() {
    # Try common interface names
    for iface in eth0 ens18 ens192 enp0s18; do
        if ip link show "$iface" &>/dev/null; then
            echo "$iface"
            return
        fi
    done
    # Fallback to first available interface
    ip route | grep default | awk '{print $5}' | head -n1
}

INTERFACE=$(get_interface)
log_message "Starting packet capture on interface: $INTERFACE"

# Continuous capture with rotation
while true; do
    TIMESTAMP=$(date +%Y%m%d-%H%M%S)
    PCAP_FILE="$PCAP_DIR/cyberrange-$TIMESTAMP.pcap"
    
    log_message "Starting capture: $PCAP_FILE"
    
    # Capture for 10 minutes or until max file size
    timeout 600 tcpdump -i "$INTERFACE" -w "$PCAP_FILE" -C 100 -W 6 \
        -s 65535 -Z root \
        'not (host 127.0.0.1 or host ::1)' 2>&1 | tee -a "$LOG_FILE" &
    
    TCPDUMP_PID=$!
    wait $TCPDUMP_PID
    
    log_message "Capture completed: $PCAP_FILE"
    
    # Remove old captures (keep last 24 hours)
    find "$PCAP_DIR" -name "*.pcap" -mtime +1 -delete 2>/dev/null
    
    sleep 30
done
EOF

    chmod +x "$SCRIPTS_DIR/packet-capture.sh"
    
    # Create systemd service
    cat << EOF > /etc/systemd/system/cyberrange-pcap.service
[Unit]
Description=CyberRange Packet Capture Service
After=network.target
Wants=network.target

[Service]
Type=simple
User=root
Group=root
ExecStart=$SCRIPTS_DIR/packet-capture.sh
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable cyberrange-pcap.service
    log "✅ Packet capture service configured"
}

# Setup network monitoring
setup_network_monitoring() {
    log "Setting up network monitoring..."
    
    # Create network monitoring script
    cat << 'EOF' > "$SCRIPTS_DIR/network-monitor.sh"
#!/bin/bash
# Network Traffic Monitor for CyberRange VM 103

LOG_FILE="/var/log/cyberrange/network-monitor.log"
STATS_FILE="/opt/cyberrange/logs/network-stats.json"
INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n1)

log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Monitor network connections
monitor_connections() {
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    # Get connection stats
    local active_connections=$(netstat -an | wc -l)
    local tcp_connections=$(netstat -an | grep tcp | wc -l)
    local udp_connections=$(netstat -an | grep udp | wc -l)
    
    # Get interface statistics
    local rx_bytes=$(cat "/sys/class/net/$INTERFACE/statistics/rx_bytes" 2>/dev/null || echo "0")
    local tx_bytes=$(cat "/sys/class/net/$INTERFACE/statistics/tx_bytes" 2>/dev/null || echo "0")
    local rx_packets=$(cat "/sys/class/net/$INTERFACE/statistics/rx_packets" 2>/dev/null || echo "0")
    local tx_packets=$(cat "/sys/class/net/$INTERFACE/statistics/tx_packets" 2>/dev/null || echo "0")
    
    # Create JSON stats
    cat << JSON_EOF > "$STATS_FILE"
{
    "timestamp": "$timestamp",
    "interface": "$INTERFACE",
    "connections": {
        "total": $active_connections,
        "tcp": $tcp_connections,
        "udp": $udp_connections
    },
    "traffic": {
        "rx_bytes": $rx_bytes,
        "tx_bytes": $tx_bytes,
        "rx_packets": $rx_packets,
        "tx_packets": $tx_packets
    }
}
JSON_EOF

    log_message "Network stats updated - Interface: $INTERFACE, Connections: $active_connections"
}

# Monitor continuously
while true; do
    monitor_connections
    sleep 60
done
EOF

    chmod +x "$SCRIPTS_DIR/network-monitor.sh"
    
    # Create systemd service for network monitoring
    cat << EOF > /etc/systemd/system/cyberrange-netmon.service
[Unit]
Description=CyberRange Network Monitor
After=network.target

[Service]
Type=simple
User=root
ExecStart=$SCRIPTS_DIR/network-monitor.sh
Restart=always
RestartSec=30

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable cyberrange-netmon.service
    log "✅ Network monitoring configured"
}

# Setup system monitoring
setup_system_monitoring() {
    log "Setting up system monitoring..."
    
    # Create system monitor script
    cat << 'EOF' > "$SCRIPTS_DIR/system-monitor.sh"
#!/bin/bash
# System Resource Monitor for CyberRange VM 103

LOG_FILE="/var/log/cyberrange/system-monitor.log"
STATS_FILE="/opt/cyberrange/logs/system-stats.json"

log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Collect system stats
collect_stats() {
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    # CPU usage
    local cpu_usage=$(top -bn1 | grep "Cpu(s)" | sed "s/.*, *\([0-9.]*\)%* id.*/\1/" | awk '{print 100 - $1}')
    
    # Memory usage
    local mem_info=$(free -m)
    local mem_total=$(echo "$mem_info" | awk '/^Mem:/ {print $2}')
    local mem_used=$(echo "$mem_info" | awk '/^Mem:/ {print $3}')
    local mem_free=$(echo "$mem_info" | awk '/^Mem:/ {print $4}')
    
    # Disk usage
    local disk_info=$(df -h / | tail -n1)
    local disk_usage=$(echo "$disk_info" | awk '{print $5}' | sed 's/%//')
    local disk_free=$(echo "$disk_info" | awk '{print $4}')
    
    # Load average
    local load_avg=$(uptime | awk -F'load average:' '{print $2}' | awk '{print $1}' | sed 's/,//')
    
    # Create JSON stats
    cat << JSON_EOF > "$STATS_FILE"
{
    "timestamp": "$timestamp",
    "cpu": {
        "usage_percent": ${cpu_usage:-0}
    },
    "memory": {
        "total_mb": $mem_total,
        "used_mb": $mem_used,
        "free_mb": $mem_free,
        "usage_percent": $(echo "scale=2; $mem_used * 100 / $mem_total" | bc -l 2>/dev/null || echo "0")
    },
    "disk": {
        "usage_percent": $disk_usage,
        "free_space": "$disk_free"
    },
    "load_average": ${load_avg:-0}
}
JSON_EOF

    log_message "System stats updated - CPU: ${cpu_usage}%, Memory: ${mem_used}MB/${mem_total}MB"
}

# Monitor continuously
while true; do
    collect_stats
    sleep 300  # Every 5 minutes
done
EOF

    chmod +x "$SCRIPTS_DIR/system-monitor.sh"
    
    # Create systemd service
    cat << EOF > /etc/systemd/system/cyberrange-sysmon.service
[Unit]
Description=CyberRange System Monitor
After=network.target

[Service]
Type=simple
User=root
ExecStart=$SCRIPTS_DIR/system-monitor.sh
Restart=always
RestartSec=30

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable cyberrange-sysmon.service
    log "✅ System monitoring configured"
}

# Setup firewall rules for lab management
setup_firewall() {
    log "Setting up firewall rules for lab management..."
    
    # Create firewall configuration
    cat << 'EOF' > "$SCRIPTS_DIR/setup-firewall.sh"
#!/bin/bash
# CyberRange Firewall Configuration for VM 103

log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

log_message "Configuring iptables for CyberRange VM 103..."

# Clear existing rules
iptables -F
iptables -X
iptables -Z

# Default policies
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT

# Allow loopback traffic
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Allow established connections
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow SSH (port 22) from local network
iptables -A INPUT -p tcp --dport 22 -s 172.16.0.0/16 -j ACCEPT

# Allow CyberRange services
iptables -A INPUT -p tcp --dport 3000 -j ACCEPT  # Frontend
iptables -A INPUT -p tcp --dport 5000 -j ACCEPT  # Backend
iptables -A INPUT -p tcp --dport 80 -j ACCEPT    # Dashboard
iptables -A INPUT -p tcp --dport 3306 -j ACCEPT  # MySQL (from local network)

# Allow lab network traffic
iptables -A INPUT -s 172.16.26.0/24 -j ACCEPT
iptables -A FORWARD -s 172.16.26.0/24 -j ACCEPT
iptables -A FORWARD -d 172.16.26.0/24 -j ACCEPT

# Log dropped packets (for monitoring)
iptables -A INPUT -j LOG --log-prefix "CYBERRANGE-DROP: " --log-level 4
iptables -A INPUT -j DROP

log_message "Firewall rules configured successfully"

# Save rules
iptables-save > /etc/iptables/rules.v4 2>/dev/null || {
    mkdir -p /etc/iptables
    iptables-save > /etc/iptables/rules.v4
}

log_message "Firewall rules saved"
EOF

    chmod +x "$SCRIPTS_DIR/setup-firewall.sh"
    bash "$SCRIPTS_DIR/setup-firewall.sh"
    log "✅ Firewall configured"
}

# Setup web dashboard
setup_dashboard() {
    log "Setting up monitoring dashboard..."
    
    # Create dashboard application
    cat << 'EOF' > "$WEB_DIR/dashboard.py"
#!/usr/bin/env python3
"""
CyberRange VM 103 Monitoring Dashboard
Simple Flask web interface for monitoring the CyberRange infrastructure
"""

from flask import Flask, render_template, jsonify
import json
import os
import psutil
import time
from datetime import datetime
import subprocess
import netifaces

app = Flask(__name__)

BASE_DIR = '/opt/cyberrange'
LOG_DIR = '/var/log/cyberrange'

def get_system_stats():
    """Get current system statistics"""
    try:
        stats = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'cpu_percent': psutil.cpu_percent(interval=1),
            'memory': dict(psutil.virtual_memory()._asdict()),
            'disk': dict(psutil.disk_usage('/')._asdict()),
            'network': {},
            'uptime': time.time() - psutil.boot_time()
        }
        
        # Network interfaces
        for interface in netifaces.interfaces():
            if interface != 'lo':
                try:
                    addrs = netifaces.ifaddresses(interface)
                    if netifaces.AF_INET in addrs:
                        stats['network'][interface] = addrs[netifaces.AF_INET][0]['addr']
                except:
                    pass
        
        return stats
    except Exception as e:
        return {'error': str(e)}

def get_service_status():
    """Check status of CyberRange services"""
    services = [
        'cyberrange-pcap',
        'cyberrange-netmon',
        'cyberrange-sysmon'
    ]
    
    status = {}
    for service in services:
        try:
            result = subprocess.run(['systemctl', 'is-active', service], 
                                  capture_output=True, text=True)
            status[service] = result.stdout.strip()
        except:
            status[service] = 'unknown'
    
    return status

def get_packet_capture_stats():
    """Get packet capture statistics"""
    pcap_dir = f"{BASE_DIR}/pcap-data"
    try:
        files = os.listdir(pcap_dir)
        pcap_files = [f for f in files if f.endswith('.pcap')]
        
        total_size = 0
        for file in pcap_files:
            filepath = os.path.join(pcap_dir, file)
            if os.path.exists(filepath):
                total_size += os.path.getsize(filepath)
        
        return {
            'total_files': len(pcap_files),
            'total_size_mb': round(total_size / (1024*1024), 2),
            'latest_file': max(pcap_files) if pcap_files else 'None'
        }
    except Exception as e:
        return {'error': str(e)}

@app.route('/')
def index():
    """Main dashboard page"""
    return render_template('dashboard.html')

@app.route('/api/status')
def api_status():
    """API endpoint for system status"""
    return jsonify({
        'system': get_system_stats(),
        'services': get_service_status(),
        'packet_capture': get_packet_capture_stats(),
        'vm_info': {
            'hostname': os.uname().nodename,
            'ip_address': '172.16.200.136'
        }
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8082, debug=False)
EOF

    # Create HTML template
    mkdir -p "$WEB_DIR/templates"
    cat << 'EOF' > "$WEB_DIR/templates/dashboard.html"
<!DOCTYPE html>
<html>
<head>
    <title>CyberRange VM 103 Monitor</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 5px; margin-bottom: 20px; }
        .container { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }
        .card { background: white; padding: 20px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        .metric { display: flex; justify-content: space-between; margin: 10px 0; }
        .value { font-weight: bold; color: #27ae60; }
        .error { color: #e74c3c; }
        .status-active { color: #27ae60; }
        .status-inactive { color: #e74c3c; }
        .refresh-btn { background: #3498db; color: white; border: none; padding: 10px 20px; border-radius: 3px; cursor: pointer; }
        .refresh-btn:hover { background: #2980b9; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🚀 CyberRange VM 103 (dhruv-main) Monitor</h1>
        <p>Real-time infrastructure monitoring for 172.16.200.136</p>
        <button class="refresh-btn" onclick="refreshData()">🔄 Refresh</button>
    </div>

    <div class="container">
        <div class="card">
            <h2>📊 System Status</h2>
            <div id="system-stats">Loading...</div>
        </div>

        <div class="card">
            <h2>🔧 Services</h2>
            <div id="services-status">Loading...</div>
        </div>

        <div class="card">
            <h2>📡 Packet Capture</h2>
            <div id="packet-stats">Loading...</div>
        </div>

        <div class="card">
            <h2>🌐 VM Information</h2>
            <div id="vm-info">Loading...</div>
        </div>
    </div>

    <script>
        function formatBytes(bytes) {
            if (bytes === 0) return '0 B';
            const k = 1024;
            const sizes = ['B', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }

        function formatUptime(seconds) {
            const days = Math.floor(seconds / 86400);
            const hours = Math.floor((seconds % 86400) / 3600);
            const minutes = Math.floor((seconds % 3600) / 60);
            return `${days}d ${hours}h ${minutes}m`;
        }

        function updateSystemStats(data) {
            const container = document.getElementById('system-stats');
            if (data.error) {
                container.innerHTML = `<div class="error">Error: ${data.error}</div>`;
                return;
            }

            container.innerHTML = `
                <div class="metric"><span>CPU Usage:</span><span class="value">${data.cpu_percent.toFixed(1)}%</span></div>
                <div class="metric"><span>Memory Used:</span><span class="value">${formatBytes(data.memory.used)} / ${formatBytes(data.memory.total)}</span></div>
                <div class="metric"><span>Memory %:</span><span class="value">${data.memory.percent.toFixed(1)}%</span></div>
                <div class="metric"><span>Disk Used:</span><span class="value">${formatBytes(data.disk.used)} / ${formatBytes(data.disk.total)}</span></div>
                <div class="metric"><span>Uptime:</span><span class="value">${formatUptime(data.uptime)}</span></div>
                <div class="metric"><span>Last Update:</span><span class="value">${data.timestamp}</span></div>
            `;
        }

        function updateServicesStatus(services) {
            const container = document.getElementById('services-status');
            let html = '';
            
            for (const [service, status] of Object.entries(services)) {
                const statusClass = status === 'active' ? 'status-active' : 'status-inactive';
                const statusIcon = status === 'active' ? '✅' : '❌';
                html += `<div class="metric"><span>${statusIcon} ${service}:</span><span class="${statusClass}">${status}</span></div>`;
            }
            
            container.innerHTML = html;
        }

        function updatePacketStats(data) {
            const container = document.getElementById('packet-stats');
            if (data.error) {
                container.innerHTML = `<div class="error">Error: ${data.error}</div>`;
                return;
            }

            container.innerHTML = `
                <div class="metric"><span>Total PCAP Files:</span><span class="value">${data.total_files}</span></div>
                <div class="metric"><span>Total Size:</span><span class="value">${data.total_size_mb} MB</span></div>
                <div class="metric"><span>Latest File:</span><span class="value">${data.latest_file}</span></div>
            `;
        }

        function updateVMInfo(data) {
            const container = document.getElementById('vm-info');
            container.innerHTML = `
                <div class="metric"><span>Hostname:</span><span class="value">${data.hostname}</span></div>
                <div class="metric"><span>IP Address:</span><span class="value">${data.ip_address}</span></div>
            `;
        }

        function refreshData() {
            fetch('/api/status')
                .then(response => response.json())
                .then(data => {
                    updateSystemStats(data.system);
                    updateServicesStatus(data.services);
                    updatePacketStats(data.packet_capture);
                    updateVMInfo(data.vm_info);
                })
                .catch(error => {
                    console.error('Error fetching data:', error);
                });
        }

        // Initial load and auto-refresh every 30 seconds
        refreshData();
        setInterval(refreshData, 30000);
    </script>
</body>
</html>
EOF

    # Create systemd service for dashboard
    cat << EOF > /etc/systemd/system/cyberrange-dashboard.service
[Unit]
Description=CyberRange Dashboard
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$WEB_DIR
ExecStart=/usr/bin/python3 $WEB_DIR/dashboard.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable cyberrange-dashboard.service
    
    log "✅ Dashboard configured - accessible at http://$VM_HOST_IP:8082"
}

# Configure log management
setup_logging() {
    log "Setting up log management..."
    
    # Create logrotate configuration
    cat << EOF > /etc/logrotate.d/cyberrange
$LOG_DIR/*.log {
    weekly
    rotate 4
    compress
    delaycompress
    missingok
    notifempty
    create 644 root root
    postrotate
        systemctl reload rsyslog
    endscript
}

$PCAP_DIR/*.pcap {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    maxage 7
}
EOF

    # Create rsyslog configuration for CyberRange
    cat << EOF > /etc/rsyslog.d/cyberrange.conf
# CyberRange logging configuration
:programname,isequal,"cyberrange" $LOG_DIR/system/cyberrange.log
:msg,contains,"CYBERRANGE-DROP:" $LOG_DIR/security/firewall.log
& stop
EOF

    systemctl restart rsyslog
    log "✅ Log management configured"
}

# Setup cron jobs for maintenance
setup_maintenance() {
    log "Setting up maintenance tasks..."
    
    # Create maintenance script
    cat << 'EOF' > "$SCRIPTS_DIR/maintenance.sh"
#!/bin/bash
# CyberRange VM 103 Maintenance Tasks

LOG_FILE="/var/log/cyberrange/maintenance.log"
BASE_DIR="/opt/cyberrange"

log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Clean old PCAP files (keep last 24 hours)
cleanup_pcap() {
    log_message "Cleaning old PCAP files..."
    find "$BASE_DIR/pcap-data" -name "*.pcap" -mtime +1 -delete
    local count=$(find "$BASE_DIR/pcap-data" -name "*.pcap" | wc -l)
    log_message "PCAP cleanup complete. $count files remaining."
}

# Clean old logs
cleanup_logs() {
    log_message "Cleaning old log files..."
    find "/var/log/cyberrange" -name "*.log" -size +100M -mtime +7 -delete
    log_message "Log cleanup complete."
}

# System health check
health_check() {
    log_message "Performing system health check..."
    
    # Check disk space
    local disk_usage=$(df / | tail -1 | awk '{print $5}' | sed 's/%//')
    if [ "$disk_usage" -gt 90 ]; then
        log_message "WARNING: Disk usage is ${disk_usage}%"
    fi
    
    # Check memory
    local mem_usage=$(free | grep Mem | awk '{printf "%.0f", $3/$2 * 100.0}')
    if [ "$mem_usage" -gt 90 ]; then
        log_message "WARNING: Memory usage is ${mem_usage}%"
    fi
    
    # Check services
    for service in cyberrange-pcap cyberrange-netmon cyberrange-sysmon cyberrange-dashboard; do
        if systemctl is-active --quiet "$service"; then
            log_message "Service $service: ACTIVE"
        else
            log_message "WARNING: Service $service is not active"
        fi
    done
    
    log_message "Health check complete."
}

# Run maintenance tasks
log_message "Starting maintenance tasks..."
cleanup_pcap
cleanup_logs
health_check
log_message "Maintenance tasks completed."
EOF

    chmod +x "$SCRIPTS_DIR/maintenance.sh"
    
    # Add to cron (run every hour)
    cat << EOF > /etc/cron.d/cyberrange-maintenance
# CyberRange maintenance tasks
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Run maintenance every hour
0 * * * * root $SCRIPTS_DIR/maintenance.sh

# Generate daily reports at midnight
0 0 * * * root $SCRIPTS_DIR/daily-report.sh
EOF

    log "✅ Maintenance tasks configured"
}

# Create configuration file
create_config() {
    log "Creating configuration file..."
    
    cat << EOF > "$BASE_DIR/config/cyberrange.conf"
# CyberRange VM 103 Configuration
# Generated: $(date)

[General]
vm_host=172.16.200.136
vm_name=dhruv-main
deployment_mode=local_infrastructure
version=phase1

[Directories]
base_dir=$BASE_DIR
log_dir=$LOG_DIR
pcap_dir=$PCAP_DIR
scripts_dir=$SCRIPTS_DIR
web_dir=$WEB_DIR

[Services]
packet_capture=enabled
network_monitoring=enabled
system_monitoring=enabled
dashboard=enabled
firewall=enabled

[Network]
management_interface=auto
lab_network=172.16.26.0/24
capture_interface=auto

[Storage]
pcap_retention_hours=24
log_retention_days=7
max_pcap_size_mb=100

[Dashboard]
enabled=true
port=8082
auto_refresh_seconds=30

[Monitoring]
system_stats_interval=300
network_stats_interval=60
packet_rotation_minutes=10
EOF

    log "✅ Configuration file created: $BASE_DIR/config/cyberrange.conf"
}

# Start all services
start_services() {
    log "Starting CyberRange services..."
    
    SERVICES=(
        "cyberrange-pcap"
        "cyberrange-netmon"
        "cyberrange-sysmon"
        "cyberrange-dashboard"
    )
    
    for service in "${SERVICES[@]}"; do
        systemctl start "$service"
        if systemctl is-active --quiet "$service"; then
            log "✅ $service started successfully"
        else
            warn "⚠️  Failed to start $service"
        fi
    done
}

# Verify installation
verify_installation() {
    log "Verifying installation..."
    
    # Check directories
    for dir in "$BASE_DIR" "$LOG_DIR" "$PCAP_DIR" "$SCRIPTS_DIR" "$WEB_DIR"; do
        if [[ -d "$dir" ]]; then
            log "✅ Directory exists: $dir"
        else
            error "❌ Directory missing: $dir"
        fi
    done
    
    # Check services
    SERVICES=("cyberrange-pcap" "cyberrange-netmon" "cyberrange-sysmon" "cyberrange-dashboard")
    for service in "${SERVICES[@]}"; do
        if systemctl is-active --quiet "$service"; then
            log "✅ Service running: $service"
        else
            warn "⚠️  Service not running: $service"
        fi
    done
    
    # Check dashboard
    sleep 5
    if curl -s -o /dev/null -w "%{http_code}" "http://localhost:8082/" | grep -q "200"; then
        log "✅ Dashboard accessible at http://$VM_HOST_IP:8082"
    else
        warn "⚠️  Dashboard not accessible"
    fi
    
    # Check packet capture
    if [[ -f "$SCRIPTS_DIR/packet-capture.sh" ]]; then
        log "✅ Packet capture script installed"
    else
        error "❌ Packet capture script missing"
    fi
}

# Create summary report
create_summary() {
    log "Creating installation summary..."
    
    SUMMARY_FILE="$BASE_DIR/installation-summary.txt"
    
    cat << EOF > "$SUMMARY_FILE"
CyberRange Phase 1 Infrastructure Installation Summary
====================================================
Date: $(date)
Target: VM 103 (dhruv-main) - $VM_HOST_IP
Installation Type: Local Infrastructure Setup

✅ INSTALLED COMPONENTS:

Infrastructure Services:
- 📡 Packet Capture Service (cyberrange-pcap)
- 🌐 Network Monitor (cyberrange-netmon)  
- 📊 System Monitor (cyberrange-sysmon)
- 🖥️  Web Dashboard (cyberrange-dashboard)

Directory Structure:
- $BASE_DIR (Base directory)
- $LOG_DIR (Logs)
- $PCAP_DIR (Packet captures)
- $SCRIPTS_DIR (Scripts)
- $WEB_DIR (Dashboard)

Network Configuration:
- VM IP: $VM_HOST_IP
- Lab Network: 172.16.26.0/24
- Firewall: Configured for lab management
- Packet Capture: Active on primary interface

Monitoring Features:
- Real-time system stats
- Network traffic monitoring
- Packet capture with rotation
- Web-based dashboard
- Automated log management

🌐 ACCESS POINTS:

Dashboard: http://$VM_HOST_IP:8082
- Real-time system monitoring
- Service status
- Packet capture statistics
- VM information

CyberRange Services:
- Frontend: http://$VM_HOST_IP:3000 (if running)
- Backend: http://$VM_HOST_IP:5000 (if running)

📁 KEY FILES:

Configuration: $BASE_DIR/config/cyberrange.conf
Main Scripts: $SCRIPTS_DIR/
Logs: $LOG_DIR/
Packet Captures: $PCAP_DIR/

🔧 MANAGEMENT COMMANDS:

Service Management:
- sudo systemctl status cyberrange-pcap
- sudo systemctl status cyberrange-netmon
- sudo systemctl status cyberrange-sysmon
- sudo systemctl status cyberrange-dashboard

Log Viewing:
- tail -f $LOG_DIR/system/cyberrange.log
- tail -f $LOG_DIR/packet-capture.log
- tail -f $LOG_DIR/network-monitor.log

Maintenance:
- $SCRIPTS_DIR/maintenance.sh (manual run)
- Automated via cron every hour

📊 MONITORING CAPABILITIES:

System Metrics:
- CPU, Memory, Disk usage
- Network statistics
- Service status
- System uptime

Network Monitoring:
- Active connections
- Traffic statistics
- Packet capture
- Firewall logs

Security Features:
- Firewall configuration
- Traffic logging
- Access control
- Log rotation

🎯 NEXT STEPS:

1. Access dashboard: http://$VM_HOST_IP:8082
2. Verify all services are running
3. Test packet capture functionality
4. Configure lab assignments in main CyberRange
5. Monitor logs and system performance

📞 SUPPORT:

Installation Log: $LOG_DIR/installation.log
System Logs: $LOG_DIR/system/
Configuration: $BASE_DIR/config/cyberrange.conf

The Phase 1 infrastructure is now ready for CyberRange lab management!
EOF

    echo
    cat "$SUMMARY_FILE"
    echo
    log "📄 Summary saved to: $SUMMARY_FILE"
}

# Main installation flow
main() {
    log "🚀 Starting CyberRange Phase 1 Infrastructure Installation..."
    
    check_permissions
    verify_environment
    setup_directories
    install_packages
    setup_packet_capture
    setup_network_monitoring
    setup_system_monitoring
    setup_firewall
    setup_dashboard
    setup_logging
    setup_maintenance
    create_config
    start_services
    verify_installation
    create_summary
    
    echo
    log "🎉 CyberRange Phase 1 Infrastructure installation completed!"
    log "🌐 Dashboard available at: http://$VM_HOST_IP:8082"
    log "📊 All monitoring services are now active"
    echo
}

# Execute main function
main "$@"

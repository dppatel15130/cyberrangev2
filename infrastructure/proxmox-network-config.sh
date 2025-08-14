#!/bin/bash
# Proxmox Network Configuration for Cyber-Warfare Mode
# This script configures vmbr0 port mirroring and firewall rules

set -euo pipefail

# Configuration variables
BRIDGE_NAME="vmbr0"
LOGSTASH_VM_ID="137"
LOGSTASH_IP="172.16.200.137"
PROXMOX_NODE="satyam"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if running on Proxmox host
check_proxmox_host() {
    if ! command -v pveversion >/dev/null 2>&1; then
        error "This script must be run on a Proxmox VE host"
        exit 1
    fi
    log "Running on Proxmox VE: $(pveversion --verbose | head -1)"
}

# Function to backup current network configuration
backup_network_config() {
    local backup_dir="/etc/pve/backup-$(date +%Y%m%d-%H%M%S)"
    log "Creating backup directory: $backup_dir"
    mkdir -p "$backup_dir"
    
    # Backup network interfaces
    cp /etc/network/interfaces "$backup_dir/"
    
    # Backup firewall configuration
    if [ -d "/etc/pve/firewall" ]; then
        cp -r /etc/pve/firewall "$backup_dir/"
    fi
    
    log "Network configuration backed up to $backup_dir"
}

# Function to configure port mirroring on vmbr0
configure_port_mirroring() {
    log "Configuring port mirroring on $BRIDGE_NAME"
    
    # Check if bridge exists
    if ! ip link show "$BRIDGE_NAME" >/dev/null 2>&1; then
        error "Bridge $BRIDGE_NAME does not exist"
        return 1
    fi
    
    # Create mirror configuration
    cat > "/tmp/mirror-setup.sh" << EOF
#!/bin/bash
# Enable port mirroring on $BRIDGE_NAME
# Traffic will be mirrored to Logstash VM

# Create a TAP interface for mirroring
ip tuntap add mode tap tap-mirror
ip link set tap-mirror up
ip link set tap-mirror master $BRIDGE_NAME

# Configure bridge to mirror all traffic
bridge fdb add 00:00:00:00:00:00 dev tap-mirror dst $LOGSTASH_IP
echo "Port mirroring configured for $BRIDGE_NAME"
EOF
    
    chmod +x "/tmp/mirror-setup.sh"
    bash "/tmp/mirror-setup.sh"
    
    # Make it persistent by adding to interfaces file
    if ! grep -q "# Cyberrange mirroring" /etc/network/interfaces; then
        cat >> /etc/network/interfaces << EOF

# Cyberrange mirroring configuration
auto tap-mirror
iface tap-mirror inet manual
    pre-up ip tuntap add mode tap tap-mirror
    up ip link set tap-mirror master $BRIDGE_NAME
    up bridge fdb add 00:00:00:00:00:00 dev tap-mirror dst $LOGSTASH_IP
    down ip link delete tap-mirror
EOF
        log "Port mirroring configuration added to /etc/network/interfaces"
    else
        warn "Port mirroring configuration already exists"
    fi
}

# Function to configure Proxmox firewall rules
configure_firewall_rules() {
    log "Configuring Proxmox firewall rules"
    
    # Create cluster firewall configuration
    mkdir -p /etc/pve/firewall
    
    # Cluster-wide firewall rules
    cat > /etc/pve/firewall/cluster.fw << EOF
[OPTIONS]
enable: 1
log_level_in: info
log_level_out: info

[ALIASES]
cyberrange_net 172.16.200.0/24
target_vm 172.16.26.128
attacker_vm 172.16.200.151
logstash_vm 172.16.200.137

[RULES]
# Allow internal cyberrange communication
IN ACCEPT -source cyberrange_net -dest cyberrange_net

# Block all outbound internet traffic
OUT DROP -dest !cyberrange_net -comment "Block internet access"

# Allow DNS resolution within network
IN ACCEPT -p udp -dport 53 -source cyberrange_net
OUT ACCEPT -p udp -dport 53 -dest cyberrange_net

# Allow NTP for time synchronization
OUT ACCEPT -p udp -dport 123 -dest cyberrange_net

# Special rules for monitoring
IN ACCEPT -source logstash_vm -comment "Allow Logstash monitoring"
OUT ACCEPT -dest logstash_vm -comment "Allow traffic to Logstash"

# Log dropped packets
OUT LOG -dest !cyberrange_net -log-level warning -comment "Log blocked internet"
EOF

    # Enable firewall on the datacenter level
    if [ -f "/etc/pve/firewall/datacenter.cfg" ]; then
        sed -i 's/enable: 0/enable: 1/' /etc/pve/firewall/datacenter.cfg 2>/dev/null || true
    else
        echo "enable: 1" > /etc/pve/firewall/datacenter.cfg
    fi
    
    log "Firewall rules configured and enabled"
}

# Function to create VM-specific firewall rules
configure_vm_firewall() {
    local vm_id=$1
    local vm_name=$2
    
    log "Configuring firewall for VM $vm_id ($vm_name)"
    
    cat > "/etc/pve/firewall/${vm_id}.fw" << EOF
[OPTIONS]
enable: 1
dhcp: 1
ipfilter: 1
log_level_in: info
log_level_out: info
macfilter: 1
ndp: 1
radv: 0

[RULES]
# Allow internal cyberrange communication
IN ACCEPT -source 172.16.200.0/24
OUT ACCEPT -dest 172.16.200.0/24

# Block all internet access
OUT DROP -dest !172.16.200.0/24 -log-level warning

# Allow specific monitoring traffic to Logstash
OUT ACCEPT -dest 172.16.200.137 -p tcp -dport 5044
OUT ACCEPT -dest 172.16.200.137 -p tcp -dport 9200
EOF

    log "Firewall configured for VM $vm_id"
}

# Function to test network configuration
test_network_config() {
    log "Testing network configuration"
    
    # Test bridge status
    if ip link show "$BRIDGE_NAME" >/dev/null 2>&1; then
        log "✓ Bridge $BRIDGE_NAME is active"
    else
        error "✗ Bridge $BRIDGE_NAME is not active"
        return 1
    fi
    
    # Test port mirroring
    if ip link show tap-mirror >/dev/null 2>&1; then
        log "✓ Port mirroring interface is active"
    else
        warn "✗ Port mirroring interface not found"
    fi
    
    # Test firewall status
    if pve-firewall status | grep -q "enabled"; then
        log "✓ Proxmox firewall is enabled"
    else
        warn "✗ Proxmox firewall is not enabled"
    fi
}

# Main execution
main() {
    log "Starting Proxmox network configuration for cyber-warfare mode"
    
    check_proxmox_host
    backup_network_config
    configure_port_mirroring
    configure_firewall_rules
    
    # Configure firewall for known VMs
    configure_vm_firewall 102 "win7-target"
    configure_vm_firewall 103 "kali-attacker"
    
    test_network_config
    
    log "Network configuration completed successfully"
    log "Please restart networking service: systemctl restart networking"
    log "Or reboot the Proxmox host for changes to take full effect"
}

# Run main function
main "$@"

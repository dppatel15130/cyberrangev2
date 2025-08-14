#!/bin/bash
# VM Discovery and Dynamic Firewall Configuration
# This script detects existing VMs and configures firewall rules for each
# Run this script on the Proxmox host as root

set -euo pipefail

# Configuration from screenshot
NETWORK_CIDR="172.16.0.0/16"
PROXMOX_IP="172.16.200.129"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

log() { echo -e "${GREEN}[$(date +'%H:%M:%S')]${NC} $1"; }
warn() { echo -e "${YELLOW}[$(date +'%H:%M:%S')] WARN:${NC} $1"; }
error() { echo -e "${RED}[$(date +'%H:%M:%S')] ERROR:${NC} $1"; }
info() { echo -e "${BLUE}[$(date +'%H:%M:%S')] INFO:${NC} $1"; }

# Function to get VM information
get_vm_info() {
    log "Discovering VMs on Proxmox host..."
    
    if ! command -v qm >/dev/null 2>&1; then
        error "Proxmox 'qm' command not found. Are you running on a Proxmox host?"
        exit 1
    fi
    
    # Get VM list with details
    echo ""
    info "Current VMs on this host:"
    qm list | while IFS= read -r line; do
        echo "  $line"
    done
    echo ""
    
    # Get just VM IDs
    local vm_ids
    vm_ids=$(qm list | awk 'NR>1 {print $1}' | grep -E '^[0-9]+$' | sort -n)
    
    if [ -z "$vm_ids" ]; then
        warn "No VMs found"
        return 1
    fi
    
    log "Found VM IDs: $(echo $vm_ids | tr '\n' ' ')"
    echo "$vm_ids"
}

# Function to get VM IP address (if available)
get_vm_ip() {
    local vm_id=$1
    local vm_ip=""
    
    # Try to get IP from qm guest cmd (if guest agent is running)
    # Skip this in offline mode since jq may not be available
    if command -v jq >/dev/null 2>&1 && qm guest cmd "$vm_id" network-get-interfaces >/dev/null 2>&1; then
        vm_ip=$(qm guest cmd "$vm_id" network-get-interfaces | jq -r '.[] | select(.name != "lo") | .["ip-addresses"][]? | select(.["ip-address-type"] == "ipv4") | .["ip-address"]' 2>/dev/null | head -1)
    fi
    
    # If that fails, try to extract from VM config
    if [ -z "$vm_ip" ]; then
        # This is a fallback - IPs are usually assigned dynamically via DHCP
        vm_ip="dynamic"
    fi
    
    echo "$vm_ip"
}

# Function to configure firewall for a VM
configure_vm_firewall() {
    local vm_id=$1
    local vm_ip=$2
    
    log "Configuring firewall for VM $vm_id (IP: $vm_ip)"
    
    # Create firewall configuration
    cat > "/etc/pve/firewall/${vm_id}.fw" << EOF
[OPTIONS]
enable: 1
dhcp: 1
ipfilter: 1
log_level_in: info
log_level_out: info
macfilter: 0
ndp: 1
radv: 0

[RULES]
# Allow internal communication within entire network
IN ACCEPT -source $NETWORK_CIDR -comment "Allow internal network"
OUT ACCEPT -dest $NETWORK_CIDR -comment "Allow internal network"

# Allow DHCP (for dynamic IP assignment)
OUT ACCEPT -p udp -dport 67 -comment "DHCP client"
OUT ACCEPT -p udp -dport 68 -comment "DHCP client"
IN ACCEPT -p udp -dport 67 -comment "DHCP server"
IN ACCEPT -p udp -dport 68 -comment "DHCP server"

# Allow DNS within network
OUT ACCEPT -p udp -dport 53 -dest $NETWORK_CIDR -comment "DNS"
OUT ACCEPT -p tcp -dport 53 -dest $NETWORK_CIDR -comment "DNS"

# Allow common services within network for cyber-warfare scenarios
OUT ACCEPT -p tcp -dport 22 -dest $NETWORK_CIDR -comment "SSH"
OUT ACCEPT -p tcp -dport 80 -dest $NETWORK_CIDR -comment "HTTP"
OUT ACCEPT -p tcp -dport 443 -dest $NETWORK_CIDR -comment "HTTPS"
OUT ACCEPT -p tcp -dport 3389 -dest $NETWORK_CIDR -comment "RDP"
OUT ACCEPT -p tcp -dport 445 -dest $NETWORK_CIDR -comment "SMB"
OUT ACCEPT -p tcp -dport 135 -dest $NETWORK_CIDR -comment "RPC"
OUT ACCEPT -p tcp -dport 139 -dest $NETWORK_CIDR -comment "NetBIOS"

# Allow ICMP within network (for ping/traceroute)
OUT ACCEPT -p icmp -dest $NETWORK_CIDR -comment "ICMP"
IN ACCEPT -p icmp -source $NETWORK_CIDR -comment "ICMP"

# CRITICAL: Block all external internet access (air-gapped security)
OUT DROP -dest !$NETWORK_CIDR -log-level warning -comment "Block internet access"

# Log all blocked attempts for cyber-warfare analysis
OUT LOG -dest !$NETWORK_CIDR -log-level info -comment "Log external access attempts"

# Additional cyber-range specific rules
# Allow common attack vectors within network for training
OUT ACCEPT -p tcp -dport 21 -dest $NETWORK_CIDR -comment "FTP"
OUT ACCEPT -p tcp -dport 23 -dest $NETWORK_CIDR -comment "Telnet"
OUT ACCEPT -p tcp -dport 25 -dest $NETWORK_CIDR -comment "SMTP"
OUT ACCEPT -p tcp -dport 110 -dest $NETWORK_CIDR -comment "POP3"
OUT ACCEPT -p tcp -dport 143 -dest $NETWORK_CIDR -comment "IMAP"
OUT ACCEPT -p tcp -dport 993 -dest $NETWORK_CIDR -comment "IMAPS"
OUT ACCEPT -p tcp -dport 995 -dest $NETWORK_CIDR -comment "POP3S"
OUT ACCEPT -p tcp -dport 1433 -dest $NETWORK_CIDR -comment "SQL Server"
OUT ACCEPT -p tcp -dport 3306 -dest $NETWORK_CIDR -comment "MySQL"
OUT ACCEPT -p tcp -dport 5432 -dest $NETWORK_CIDR -comment "PostgreSQL"
EOF

    log "✓ Firewall configured for VM $vm_id"
}

# Function to create VM inventory
create_vm_inventory() {
    local vm_list=$1
    local inventory_file="/opt/cyberrange/vm-inventory.json"
    
    log "Creating VM inventory..."
    
    mkdir -p /opt/cyberrange
    
    cat > "$inventory_file" << 'EOF'
{
  "cyberrange_vms": {
    "network": "172.16.0.0/16",
    "proxmox_host": "172.16.200.129",
    "discovery_time": "$(date -Iseconds)",
    "vms": [
EOF

    local first=true
    for vm_id in $vm_list; do
        local vm_name=""
        local vm_status=""
        local vm_ip=""
        
        # Get VM details
        if qm config "$vm_id" >/dev/null 2>&1; then
            vm_name=$(qm config "$vm_id" | grep -E '^name:' | cut -d' ' -f2 || echo "vm-$vm_id")
            vm_status=$(qm status "$vm_id" | awk '{print $2}' || echo "unknown")
            vm_ip=$(get_vm_ip "$vm_id")
        fi
        
        # Add comma for JSON formatting (except first entry)
        if [ "$first" = false ]; then
            echo "," >> "$inventory_file"
        fi
        first=false
        
        cat >> "$inventory_file" << EOF
      {
        "id": $vm_id,
        "name": "$vm_name",
        "status": "$vm_status",
        "ip": "$vm_ip",
        "firewall_configured": true
      }
EOF
    done
    
    cat >> "$inventory_file" << 'EOF'
    ]
  }
}
EOF

    # Replace the date placeholder with actual date
    sed -i "s/\$(date -Iseconds)/$(date -Iseconds)/" "$inventory_file"
    
    log "✓ VM inventory saved to $inventory_file"
}

# Function to test firewall configuration
test_firewall_config() {
    local vm_list=$1
    
    log "Testing firewall configuration..."
    
    local total=0
    local configured=0
    
    for vm_id in $vm_list; do
        ((total++))
        if [ -f "/etc/pve/firewall/${vm_id}.fw" ]; then
            ((configured++))
            log "✓ VM $vm_id firewall configuration exists"
        else
            warn "✗ VM $vm_id firewall configuration missing"
        fi
    done
    
    log "Firewall configuration: $configured/$total VMs configured"
    
    # Test if firewall service is running
    if systemctl is-active --quiet pve-firewall; then
        log "✓ Proxmox firewall service is active"
    else
        warn "✗ Proxmox firewall service is not active"
        log "  Attempting to start firewall service..."
        systemctl start pve-firewall || warn "Failed to start pve-firewall"
    fi
}

# Function to display cyber-warfare configuration summary
display_summary() {
    local vm_list=$1
    
    echo ""
    info "═════════════════════════════════════════════"
    info "  CyberRange VM Firewall Configuration"
    info "═════════════════════════════════════════════"
    echo ""
    
    info "Network Configuration:"
    info "• Network CIDR: $NETWORK_CIDR"
    info "• Proxmox Host: $PROXMOX_IP"
    info "• Bridge: vmbr0 (existing)"
    echo ""
    
    info "Security Configuration:"
    info "✅ Internet access: BLOCKED (air-gapped)"
    info "✅ Internal communication: ALLOWED"
    info "✅ Attack vectors: ENABLED within network"
    info "✅ Logging: ALL external attempts logged"
    echo ""
    
    info "Configured VMs:"
    for vm_id in $vm_list; do
        local vm_name=$(qm config "$vm_id" 2>/dev/null | grep -E '^name:' | cut -d' ' -f2 || echo "vm-$vm_id")
        local vm_status=$(qm status "$vm_id" 2>/dev/null | awk '{print $2}' || echo "unknown")
        local vm_ip=$(get_vm_ip "$vm_id")
        
        info "• VM $vm_id ($vm_name): $vm_status, IP: $vm_ip"
    done
    echo ""
    
    info "Monitoring:"
    info "• Firewall logs: /var/log/pve-firewall.log"
    info "• VM inventory: /opt/cyberrange/vm-inventory.json"
    info "• Configuration: /etc/pve/firewall/"
    echo ""
    
    info "Cyber-Warfare Ready!"
    info "VMs can now communicate within the network but cannot reach the internet."
}

# Main function
main() {
    info "CyberRange VM Firewall Configuration"
    info "======================================"
    
    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root"
        exit 1
    fi
    
    # Check if on Proxmox
    if ! command -v pveversion >/dev/null 2>&1; then
        error "This script must be run on a Proxmox VE host"
        exit 1
    fi
    
    log "Running on: $(pveversion --verbose | head -1)"
    
    # Get VM list
    local vm_list
    vm_list=$(get_vm_info)
    
    if [ -z "$vm_list" ]; then
        warn "No VMs found to configure"
        exit 0
    fi
    
    # Configure firewall for each VM
    log "Configuring firewall for all VMs..."
    for vm_id in $vm_list; do
        local vm_ip
        vm_ip=$(get_vm_ip "$vm_id")
        configure_vm_firewall "$vm_id" "$vm_ip"
    done
    
    # Create VM inventory
    create_vm_inventory "$vm_list"
    
    # Test configuration
    test_firewall_config "$vm_list"
    
    # Reload firewall
    log "Reloading Proxmox firewall..."
    pve-firewall restart || warn "Could not restart pve-firewall"
    
    # Display summary
    display_summary "$vm_list"
    
    log "✅ VM firewall configuration completed successfully!"
}

# Run main function
main "$@"

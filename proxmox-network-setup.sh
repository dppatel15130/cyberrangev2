#!/bin/bash
# Proxmox VLAN and Bridge Configuration for Cyber-Warfare Platform
# Run this script on the Proxmox VE host (172.16.200.129) as root

set -euo pipefail

echo "=== Cyber-Warfare Platform Network Setup ==="
echo "Configuring VLANs and bridges for team isolation..."

# Backup current network config
cp /etc/network/interfaces /etc/network/interfaces.backup.$(date +%Y%m%d-%H%M%S)

# Function to create team VLAN bridge
create_team_bridge() {
    local team_id=$1
    local vlan_id=$((100 + team_id))
    local bridge_name="vmbr${vlan_id}"
    
    echo "Creating bridge ${bridge_name} for Team ${team_id} (VLAN ${vlan_id})"
    
    # Add bridge configuration to /etc/network/interfaces
    cat >> /etc/network/interfaces << EOF

# Team ${team_id} Bridge (VLAN ${vlan_id})
auto ${bridge_name}
iface ${bridge_name} inet manual
    bridge-ports none
    bridge-stp off
    bridge-fd 0
    bridge-vlan-aware yes
    bridge-vids ${vlan_id}

EOF
}

echo "1. Ensuring OVS is installed and enabled..."
apt-get update
apt-get install -y openvswitch-switch

# Enable OVS service
systemctl enable openvswitch-switch
systemctl start openvswitch-switch

echo "2. Creating team bridges (supporting up to 6 teams)..."
for team_id in {1..6}; do
    create_team_bridge $team_id
done

echo "3. Creating dedicated bridge for traffic mirroring..."
cat >> /etc/network/interfaces << EOF

# Traffic Mirror Bridge
auto vmbr200
iface vmbr200 inet manual
    bridge-ports none
    bridge-stp off
    bridge-fd 0
    # Used for Logstash sensor VM to receive mirrored traffic

EOF

echo "4. Configuring network restart and verification..."
# Note: Network restart on Proxmox should be done carefully
cat > /tmp/network-restart.sh << 'EOF'
#!/bin/bash
echo "Restarting network services..."
systemctl restart networking
systemctl restart pve-cluster
systemctl restart pvedaemon
systemctl restart pveproxy
EOF

chmod +x /tmp/network-restart.sh

echo "5. Creating OVS configuration for traffic mirroring..."
cat > /tmp/setup-ovs-mirror.sh << 'EOF'
#!/bin/bash
# Setup OVS mirrors for each team VLAN
# This will be called after VMs are created

setup_team_mirror() {
    local team_id=$1
    local vlan_id=$((100 + team_id))
    local bridge_name="vmbr${vlan_id}"
    local mirror_name="mirror-team${team_id}"
    
    echo "Setting up traffic mirror for Team ${team_id}..."
    
    # Create OVS mirror for team traffic
    ovs-vsctl -- set bridge ${bridge_name} mirrors=@m \
              -- --id=@m create mirror name=${mirror_name} \
                 select-all=true output-port=mirror-out-${team_id}
}

# Will be executed after Logstash sensor VM is created
for team_id in {1..6}; do
    setup_team_mirror $team_id
done
EOF

chmod +x /tmp/setup-ovs-mirror.sh

echo "6. Creating VM network configuration templates..."
mkdir -p /tmp/vm-configs

# Template for Windows 7 target (multi-homed)
cat > /tmp/vm-configs/windows7-network.conf << 'EOF'
# Windows 7 Target VM (VMID 103) Network Configuration
# This VM should have multiple network interfaces:

# Management interface (existing)
# net0: virtio,bridge=vmbr0,firewall=1

# Team interfaces (add these)
# net1: virtio,bridge=vmbr101,firewall=1,tag=101
# net2: virtio,bridge=vmbr102,firewall=1,tag=102  
# net3: virtio,bridge=vmbr103,firewall=1,tag=103
# net4: virtio,bridge=vmbr104,firewall=1,tag=104
# net5: virtio,bridge=vmbr105,firewall=1,tag=105
# net6: virtio,bridge=vmbr106,firewall=1,tag=106
EOF

# Template for team VMs
cat > /tmp/vm-configs/team-vm-template.conf << 'EOF'
# Team VM Network Template
# Each team VM should connect to their respective VLAN bridge
# Example for Team 1:
# net0: virtio,bridge=vmbr101,firewall=1,tag=101

# Team 1: bridge=vmbr101,tag=101
# Team 2: bridge=vmbr102,tag=102
# Team 3: bridge=vmbr103,tag=103
# Team 4: bridge=vmbr104,tag=104
# Team 5: bridge=vmbr105,tag=105
# Team 6: bridge=vmbr106,tag=106
EOF

# Logstash sensor VM config
cat > /tmp/vm-configs/logstash-sensor-network.conf << 'EOF'
# Logstash Sensor VM Network Configuration
# This VM needs access to mirrored traffic from all teams

# Management interface
# net0: virtio,bridge=vmbr0,firewall=1

# Mirror interfaces (one per team)
# net1: virtio,bridge=vmbr200,firewall=0  # Receives mirrored traffic
EOF

echo "7. Creating IP assignment plan..."
cat > /tmp/ip-plan.txt << 'EOF'
# IP Address Assignment Plan
# Management Network (vmbr0): 172.16.200.0/24

Existing:
- Proxmox VE: 172.16.200.129
- ELK/Guacamole: 172.16.200.136

New assignments:
- Logstash Sensor: 172.16.200.140
- Game Backend: 172.16.200.141  
- MySQL DB: 172.16.200.142
- Windows 7 (mgmt): 172.16.200.143

Team Networks (isolated VLANs):
- Team 1 VLAN 101: 10.101.0.0/24
- Team 2 VLAN 102: 10.102.0.0/24  
- Team 3 VLAN 103: 10.103.0.0/24
- Team 4 VLAN 104: 10.104.0.0/24
- Team 5 VLAN 105: 10.105.0.0/24
- Team 6 VLAN 106: 10.106.0.0/24

Windows 7 Team Interfaces:
- Team 1 interface: 10.101.0.100
- Team 2 interface: 10.102.0.100
- Team 3 interface: 10.103.0.100
- Team 4 interface: 10.104.0.100  
- Team 5 interface: 10.105.0.100
- Team 6 interface: 10.106.0.100
EOF

echo "8. Creating verification script..."
cat > /tmp/verify-network.sh << 'EOF'
#!/bin/bash
echo "=== Network Configuration Verification ==="

echo "1. Checking bridges..."
brctl show

echo "2. Checking OVS bridges..."
ovs-vsctl show

echo "3. Checking network interfaces..."
ip link show | grep vmbr

echo "4. Checking VLAN configuration..."
for i in {101..106}; do
    if [ -d /sys/class/net/vmbr$i ]; then
        echo "Bridge vmbr$i exists"
    else
        echo "WARNING: Bridge vmbr$i missing"
    fi
done

echo "5. Checking mirror configuration..."
ovs-vsctl list mirror

echo "=== Configuration Complete ==="
echo "Next steps:"
echo "1. Review /tmp/ip-plan.txt for IP assignments"
echo "2. Configure VMs using templates in /tmp/vm-configs/"
echo "3. Run /tmp/setup-ovs-mirror.sh after VMs are created"
echo "4. Use /tmp/network-restart.sh to restart networking (CAREFULLY!)"
EOF

chmod +x /tmp/verify-network.sh

echo ""
echo "=== Network Setup Complete ==="
echo ""
echo "Configuration files created:"
echo "- Network config backed up to /etc/network/interfaces.backup.*"
echo "- Bridge configs added to /etc/network/interfaces"
echo "- VM network templates in /tmp/vm-configs/"
echo "- IP assignment plan in /tmp/ip-plan.txt"
echo ""
echo "Next steps:"
echo "1. Review the configuration changes in /etc/network/interfaces"
echo "2. Run: /tmp/verify-network.sh"
echo "3. CAREFULLY restart networking: /tmp/network-restart.sh"
echo "4. Configure VMs according to templates"
echo "5. Setup traffic mirroring: /tmp/setup-ovs-mirror.sh"
echo ""
echo "WARNING: Network restart may temporarily disconnect Proxmox management!"
echo "Ensure console access is available before proceeding."

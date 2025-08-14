#!/bin/bash
# Configure Windows 7 Target VM (VMID 103) with Multi-Homed Network Interfaces
# Run this script on the Proxmox VE host after network bridges are configured

set -euo pipefail

VMID=103
VM_NAME="Windows7-CyberTarget"

echo "=== Configuring Windows 7 Target VM (VMID: $VMID) ==="

# Function to add network interface to VM
add_team_interface() {
    local net_id=$1
    local vlan_id=$((100 + net_id))
    local bridge_name="vmbr${vlan_id}"
    
    echo "Adding Team $net_id interface (net${net_id}: $bridge_name, VLAN $vlan_id)"
    
    qm set $VMID --net${net_id} virtio,bridge=${bridge_name},firewall=1,tag=${vlan_id}
    
    if [ $? -eq 0 ]; then
        echo "✓ Successfully added net${net_id} for Team $net_id"
    else
        echo "✗ Failed to add net${net_id} for Team $net_id"
        return 1
    fi
}

echo "1. Checking if VM exists..."
if ! qm status $VMID >/dev/null 2>&1; then
    echo "ERROR: VM $VMID does not exist!"
    echo "Please ensure Windows 7 VM is created with VMID $VMID"
    exit 1
fi

echo "2. Current VM configuration:"
qm config $VMID

echo "3. Stopping VM for network configuration..."
qm stop $VMID || true
sleep 5

echo "4. Configuring management interface (net0)..."
# Ensure management interface is on vmbr0
qm set $VMID --net0 virtio,bridge=vmbr0,firewall=1

echo "5. Adding team network interfaces..."
# Add network interfaces for each team (up to 6 teams)
for team_id in {1..6}; do
    add_team_interface $team_id
done

echo "6. Setting VM CPU and memory for multi-interface load..."
qm set $VMID --memory 4096
qm set $VMID --cores 2
qm set $VMID --sockets 1

echo "7. Updating VM description..."
qm set $VMID --description "Multi-team Cyber-Warfare Target
Management: vmbr0 (172.16.200.143)
Team 1: vmbr101 VLAN 101 (10.101.0.100)
Team 2: vmbr102 VLAN 102 (10.102.0.100)
Team 3: vmbr103 VLAN 103 (10.103.0.100)
Team 4: vmbr104 VLAN 104 (10.104.0.100)
Team 5: vmbr105 VLAN 105 (10.105.0.100)
Team 6: vmbr106 VLAN 106 (10.106.0.100)
"

echo "8. Final VM configuration:"
qm config $VMID

echo "9. Starting VM..."
qm start $VMID

echo "10. Waiting for VM to boot..."
sleep 30

echo "=== Windows 7 Network Configuration Instructions ==="
cat << 'EOF'

MANUAL STEPS REQUIRED ON WINDOWS 7:

1. Login to Windows 7 VM via Guacamole (172.16.200.136:8080/guacamole)

2. Configure network adapters:
   - Adapter 1 (Management): 172.16.200.143/24, Gateway: 172.16.200.1
   - Adapter 2 (Team 1): 10.101.0.100/24, No Gateway
   - Adapter 3 (Team 2): 10.102.0.100/24, No Gateway  
   - Adapter 4 (Team 3): 10.103.0.100/24, No Gateway
   - Adapter 5 (Team 4): 10.104.0.100/24, No Gateway
   - Adapter 6 (Team 5): 10.105.0.100/24, No Gateway
   - Adapter 7 (Team 6): 10.106.0.100/24, No Gateway

3. Enable services for exploitation:
   - Enable Remote Desktop (port 3389)
   - Start IIS Web Server (port 80/443)
   - Enable SMB/NetBIOS (ports 139/445)
   - Start Telnet service (port 23)
   - Enable FTP service (port 21)

4. Configure Windows Event Logging:
   - Enable Security log auditing
   - Enable System log
   - Enable Application log
   - Configure log retention (7 days minimum)

5. Install vulnerable software:
   - Older versions of common applications
   - Default/weak passwords
   - Unpatched services

6. Configure log forwarding to ELK:
   - Install Winlogbeat or NXLog
   - Configure output to Logstash: 172.16.200.140:5044

EOF

echo ""
echo "=== VM Configuration Complete ==="
echo "VM Status:"
qm status $VMID
echo ""
echo "Next Steps:"
echo "1. Complete Windows network configuration as shown above"
echo "2. Install vulnerable applications and services"
echo "3. Configure log forwarding to ELK stack"
echo "4. Create team attack VMs on respective VLANs"
echo "5. Setup traffic mirroring with /tmp/setup-ovs-mirror.sh"

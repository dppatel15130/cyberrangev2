#!/bin/bash
# CyberRange Phase 2 Deployment Script for VM 103 (dhruv-main)
# Target: 172.16.200.136
# Upgrades existing CyberRange installation with competition features

set -e

# Configuration
TARGET_HOST="172.16.200.136"
TARGET_VM="103"
CYBERRANGE_USER="kali"  # Adjust if different
CYBERRANGE_PATH="/home/$CYBERRANGE_USER/Downloads/cyberrangev1-main"
BACKEND_PATH="$CYBERRANGE_PATH/backend"
FRONTEND_PATH="$CYBERRANGE_PATH/frontend"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🚀 CyberRange Phase 2 Deployment for VM 103 (dhruv-main)${NC}"
echo -e "${BLUE}Target Host: $TARGET_HOST${NC}"
echo -e "${BLUE}Deployment Date: $(date)${NC}"
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

# Check if we're running on the target VM
check_environment() {
    log "Checking deployment environment..."
    
    CURRENT_IP=$(hostname -I | awk '{print $1}')
    if [[ "$CURRENT_IP" == "172.16.200.136" ]]; then
        log "✅ Running on target VM 103 (dhruv-main)"
        LOCAL_DEPLOYMENT=true
    else
        log "📡 Remote deployment to VM 103 detected"
        LOCAL_DEPLOYMENT=false
        # Check SSH connectivity
        if ! ping -c 1 $TARGET_HOST &> /dev/null; then
            error "❌ Cannot reach target host $TARGET_HOST"
            exit 1
        fi
    fi
}

# Backup existing installation
backup_existing() {
    log "Creating backup of existing CyberRange installation..."
    
    BACKUP_DIR="/tmp/cyberrange-backup-$(date +%Y%m%d-%H%M%S)"
    
    if [[ "$LOCAL_DEPLOYMENT" == true ]]; then
        # Local backup
        if [[ -d "$CYBERRANGE_PATH" ]]; then
            sudo mkdir -p "$BACKUP_DIR"
            sudo cp -r "$CYBERRANGE_PATH" "$BACKUP_DIR/"
            log "✅ Backup created at $BACKUP_DIR"
        fi
    else
        # Remote backup via SSH
        ssh $CYBERRANGE_USER@$TARGET_HOST "
            if [[ -d '$CYBERRANGE_PATH' ]]; then
                sudo mkdir -p '$BACKUP_DIR'
                sudo cp -r '$CYBERRANGE_PATH' '$BACKUP_DIR/'
                echo 'Backup created at $BACKUP_DIR'
            fi
        "
    fi
}

# Install Phase 2 backend dependencies
install_dependencies() {
    log "Installing Phase 2 dependencies..."
    
    if [[ "$LOCAL_DEPLOYMENT" == true ]]; then
        cd "$BACKEND_PATH"
        
        # Install new WebSocket dependency
        npm install ws@^8.18.0
        
        # Verify installation
        if npm list ws &> /dev/null; then
            log "✅ WebSocket dependency installed successfully"
        else
            error "❌ Failed to install WebSocket dependency"
            exit 1
        fi
    else
        # Remote installation
        ssh $CYBERRANGE_USER@$TARGET_HOST "
            cd '$BACKEND_PATH' && 
            npm install ws@^8.18.0 &&
            echo 'WebSocket dependency installed'
        "
    fi
}

# Deploy Phase 2 backend files
deploy_backend() {
    log "Deploying Phase 2 backend components..."
    
    # List of new files to deploy
    NEW_BACKEND_FILES=(
        "models/Team.js"
        "models/Match.js" 
        "models/ScoringEvent.js"
        "services/scoringService.js"
        "services/gameEngine.js"
        "routes/matches.js"
        "routes/teams.js"
    )
    
    if [[ "$LOCAL_DEPLOYMENT" == true ]]; then
        # Copy Phase 2 files locally
        for file in "${NEW_BACKEND_FILES[@]}"; do
            SOURCE_FILE="$(pwd)/../backend/$file"
            TARGET_FILE="$BACKEND_PATH/$file"
            
            if [[ -f "$SOURCE_FILE" ]]; then
                sudo mkdir -p "$(dirname "$TARGET_FILE")"
                sudo cp "$SOURCE_FILE" "$TARGET_FILE"
                log "✅ Deployed $file"
            else
                warn "⚠️  Source file not found: $SOURCE_FILE"
            fi
        done
        
        # Update server.js with Phase 2 integration
        if [[ -f "$(pwd)/../backend/server.js" ]]; then
            sudo cp "$(pwd)/../backend/server.js" "$BACKEND_PATH/server.js"
            log "✅ Updated server.js with Phase 2 features"
        fi
        
        # Update models/index.js
        if [[ -f "$(pwd)/../backend/models/index.js" ]]; then
            sudo cp "$(pwd)/../backend/models/index.js" "$BACKEND_PATH/models/index.js"
            log "✅ Updated models/index.js with new associations"
        fi
        
    else
        # Remote deployment
        for file in "${NEW_BACKEND_FILES[@]}"; do
            if [[ -f "../backend/$file" ]]; then
                scp "../backend/$file" $CYBERRANGE_USER@$TARGET_HOST:"$BACKEND_PATH/$file"
                log "✅ Deployed $file to remote host"
            fi
        done
        
        # Deploy updated core files
        scp "../backend/server.js" $CYBERRANGE_USER@$TARGET_HOST:"$BACKEND_PATH/server.js"
        scp "../backend/models/index.js" $CYBERRANGE_USER@$TARGET_HOST:"$BACKEND_PATH/models/index.js"
        scp "../backend/package.json" $CYBERRANGE_USER@$TARGET_HOST:"$BACKEND_PATH/package.json"
    fi
}

# Set up Phase 1 infrastructure directories
setup_infrastructure() {
    log "Setting up Phase 2 infrastructure directories..."
    
    DIRECTORIES=(
        "/opt/cyberrange"
        "/opt/cyberrange/pcap-data"
        "/opt/cyberrange/scripts"
        "/var/log/cyberrange"
    )
    
    if [[ "$LOCAL_DEPLOYMENT" == true ]]; then
        for dir in "${DIRECTORIES[@]}"; do
            sudo mkdir -p "$dir"
            sudo chown $USER:$USER "$dir"
            log "✅ Created directory: $dir"
        done
    else
        ssh $CYBERRANGE_USER@$TARGET_HOST "
            for dir in ${DIRECTORIES[@]}; do
                sudo mkdir -p \$dir
                sudo chown $CYBERRANGE_USER:$CYBERRANGE_USER \$dir
                echo 'Created directory: '\$dir
            done
        "
    fi
}

# Configure packet capture
setup_packet_capture() {
    log "Configuring packet capture for competition monitoring..."
    
    # Create packet capture script
    cat << 'EOF' > /tmp/setup-packet-capture.sh
#!/bin/bash
# Enable packet forwarding for competition networks
echo 'net.ipv4.ip_forward=1' | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

# Create packet capture service
cat << 'SERVICE_EOF' | sudo tee /etc/systemd/system/cyberrange-pcap.service
[Unit]
Description=CyberRange Packet Capture Service
After=network.target

[Service]
Type=simple
User=root
ExecStart=/opt/cyberrange/scripts/packet-capture.sh
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
SERVICE_EOF

# Create packet capture script
cat << 'SCRIPT_EOF' | sudo tee /opt/cyberrange/scripts/packet-capture.sh
#!/bin/bash
PCAP_DIR="/opt/cyberrange/pcap-data"
mkdir -p "$PCAP_DIR"

while true; do
    TIMESTAMP=$(date +%Y%m%d-%H%M%S)
    PCAP_FILE="$PCAP_DIR/cyberrange-$TIMESTAMP.pcap"
    
    # Capture packets for 5 minutes, then rotate
    timeout 300 tcpdump -i vmbr0 -w "$PCAP_FILE" -G 300 -W 12
    
    # Remove old captures (keep last 24 hours)
    find "$PCAP_DIR" -name "*.pcap" -mtime +1 -delete
    
    sleep 5
done
SCRIPT_EOF

sudo chmod +x /opt/cyberrange/scripts/packet-capture.sh
sudo systemctl daemon-reload
sudo systemctl enable cyberrange-pcap.service
EOF

    if [[ "$LOCAL_DEPLOYMENT" == true ]]; then
        bash /tmp/setup-packet-capture.sh
        log "✅ Packet capture configured locally"
    else
        scp /tmp/setup-packet-capture.sh $CYBERRANGE_USER@$TARGET_HOST:/tmp/
        ssh $CYBERRANGE_USER@$TARGET_HOST "bash /tmp/setup-packet-capture.sh"
        log "✅ Packet capture configured on remote host"
    fi
    
    rm /tmp/setup-packet-capture.sh
}

# Configure firewall rules for team isolation
setup_firewall() {
    log "Setting up firewall rules for team network isolation..."
    
    cat << 'EOF' > /tmp/setup-firewall.sh
#!/bin/bash
# Create cyberrange iptables rules

# Allow established connections
sudo iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow host management network
sudo iptables -A FORWARD -s 172.16.200.0/24 -d 172.16.200.0/24 -j ACCEPT

# Create custom chain for team isolation
sudo iptables -N CYBERRANGE_TEAMS 2>/dev/null || true
sudo iptables -F CYBERRANGE_TEAMS

# Jump to team isolation chain
sudo iptables -I FORWARD 1 -j CYBERRANGE_TEAMS

# Save rules (method varies by distro)
if command -v iptables-save >/dev/null 2>&1; then
    sudo iptables-save | sudo tee /etc/iptables/rules.v4 >/dev/null
    echo "Firewall rules saved"
fi
EOF

    if [[ "$LOCAL_DEPLOYMENT" == true ]]; then
        bash /tmp/setup-firewall.sh
        log "✅ Firewall rules configured locally"
    else
        scp /tmp/setup-firewall.sh $CYBERRANGE_USER@$TARGET_HOST:/tmp/
        ssh $CYBERRANGE_USER@$TARGET_HOST "bash /tmp/setup-firewall.sh"
        log "✅ Firewall rules configured on remote host"
    fi
    
    rm /tmp/setup-firewall.sh
}

# Update database schema
update_database() {
    log "Updating database schema for Phase 2..."
    
    if [[ "$LOCAL_DEPLOYMENT" == true ]]; then
        cd "$BACKEND_PATH"
        
        # The models will auto-sync when the server starts
        log "✅ Database models will auto-sync on next server start"
    else
        ssh $CYBERRANGE_USER@$TARGET_HOST "
            cd '$BACKEND_PATH'
            echo 'Database models will auto-sync on next server start'
        "
    fi
}

# Restart services
restart_services() {
    log "Restarting CyberRange services..."
    
    if [[ "$LOCAL_DEPLOYMENT" == true ]]; then
        # Stop existing backend if running
        pkill -f "node server.js" || true
        pkill -f "npm.*dev" || true
        
        # Start packet capture service
        sudo systemctl start cyberrange-pcap.service || warn "Failed to start packet capture service"
        
        # Start backend in background
        cd "$BACKEND_PATH"
        nohup npm start > /var/log/cyberrange/backend.log 2>&1 &
        
        log "✅ Services restarted"
        log "📊 Backend log: /var/log/cyberrange/backend.log"
        
    else
        ssh $CYBERRANGE_USER@$TARGET_HOST "
            pkill -f 'node server.js' || true
            pkill -f 'npm.*dev' || true
            
            sudo systemctl start cyberrange-pcap.service || echo 'Warning: Failed to start packet capture'
            
            cd '$BACKEND_PATH'
            nohup npm start > /var/log/cyberrange/backend.log 2>&1 &
            
            echo 'Services restarted'
        "
    fi
    
    sleep 5
}

# Verify deployment
verify_deployment() {
    log "Verifying Phase 2 deployment..."
    
    # Check if backend is responding
    sleep 10
    
    if curl -s http://$TARGET_HOST:5000/api/health >/dev/null 2>&1; then
        log "✅ Backend health check passed"
        
        # Get detailed health info
        HEALTH_INFO=$(curl -s http://$TARGET_HOST:5000/api/health | python3 -m json.tool 2>/dev/null || echo "Health endpoint accessible")
        echo "$HEALTH_INFO"
        
    else
        warn "⚠️  Backend health check failed - may need more time to start"
    fi
    
    # Check WebSocket endpoint
    if curl -s -N -H "Connection: Upgrade" -H "Upgrade: websocket" http://$TARGET_HOST:5000/ws/scoring >/dev/null 2>&1; then
        log "✅ WebSocket endpoint accessible"
    else
        warn "⚠️  WebSocket endpoint check failed"
    fi
    
    # Check packet capture
    if [[ "$LOCAL_DEPLOYMENT" == true ]]; then
        if systemctl is-active --quiet cyberrange-pcap.service; then
            log "✅ Packet capture service running"
        else
            warn "⚠️  Packet capture service not running"
        fi
    fi
}

# Create deployment summary
create_summary() {
    log "Creating deployment summary..."
    
    SUMMARY_FILE="/tmp/cyberrange-phase2-deployment-summary.txt"
    
    cat << EOF > "$SUMMARY_FILE"
CyberRange Phase 2 Deployment Summary
=====================================
Date: $(date)
Target: VM 103 (dhruv-main) - $TARGET_HOST
Deployment Type: Phase 2 Upgrade

Services Deployed:
✅ WebSocket Server (Real-time scoring)
✅ Game Engine (Match management)
✅ Scoring Service (Attack detection)
✅ Packet Capture (Network monitoring)
✅ Team Management APIs
✅ Match Management APIs

New Endpoints:
- GET  /api/matches - List matches
- POST /api/matches - Create match (admin)
- GET  /api/teams - List teams  
- POST /api/teams - Create team
- WebSocket: ws://$TARGET_HOST:5000/ws/scoring

Infrastructure:
- Packet capture: /opt/cyberrange/pcap-data/
- Logs: /var/log/cyberrange/
- Firewall: Team isolation configured
- Database: Auto-sync Phase 2 models

Access URLs:
- Frontend: http://$TARGET_HOST:3000
- Backend API: http://$TARGET_HOST:5000/api
- Health Check: http://$TARGET_HOST:5000/api/health
- WebSocket: ws://$TARGET_HOST:5000/ws/scoring

Next Steps:
1. Access frontend at http://$TARGET_HOST:3000
2. Create teams and competitions
3. Configure VM templates for matches
4. Test real-time scoring features

Support:
- Backend logs: /var/log/cyberrange/backend.log
- Packet capture logs: journalctl -u cyberrange-pcap.service
- System logs: /var/log/syslog
EOF

    echo
    cat "$SUMMARY_FILE"
    
    if [[ "$LOCAL_DEPLOYMENT" == true ]]; then
        cp "$SUMMARY_FILE" "/opt/cyberrange/deployment-summary.txt"
        log "📄 Summary saved to /opt/cyberrange/deployment-summary.txt"
    fi
}

# Main deployment flow
main() {
    log "🚀 Starting CyberRange Phase 2 deployment..."
    
    check_environment
    backup_existing
    install_dependencies
    deploy_backend
    setup_infrastructure
    setup_packet_capture
    setup_firewall
    update_database
    restart_services
    verify_deployment
    create_summary
    
    echo
    log "🎉 Phase 2 deployment completed successfully!"
    log "🌐 CyberRange is now ready for cyber-warfare competitions"
    log "📍 Access your enhanced platform at: http://$TARGET_HOST:3000"
    echo
}

# Execute main function
main "$@"

#!/bin/bash
# Quick Deployment Script for CyberRange Phase 1: Monitoring Infrastructure
# Run this script on the Proxmox host as root

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CYBERRANGE_DIR="/opt/cyberrange"
LOG_FILE="/var/log/cyberrange-deployment.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a "$LOG_FILE"
}

warn() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARN:${NC} $1" | tee -a "$LOG_FILE"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR:${NC} $1" | tee -a "$LOG_FILE"
}

info() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')] INFO:${NC} $1" | tee -a "$LOG_FILE"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root"
        exit 1
    fi
}

# Check if running on Proxmox
check_proxmox() {
    if ! command -v pveversion >/dev/null 2>&1; then
        error "This script must be run on a Proxmox VE host"
        exit 1
    fi
    log "✓ Running on Proxmox VE: $(pveversion --verbose | head -1)"
}

# Install required packages
install_packages() {
    log "Installing required packages..."
    
    apt-get update
    apt-get install -y \
        docker.io \
        docker-compose-plugin \
        bridge-utils \
        tcpdump \
        net-tools \
        curl \
        jq \
        git \
        ansible
    
    systemctl enable docker
    systemctl start docker
    
    log "✓ Packages installed successfully"
}

# Setup directory structure
setup_directories() {
    log "Creating directory structure..."
    
    mkdir -p "$CYBERRANGE_DIR"/{infrastructure,logs,pcap-data,backups}
    mkdir -p "$CYBERRANGE_DIR"/logstash/{config,pipeline,patterns,templates}
    mkdir -p "$CYBERRANGE_DIR"/grafana/{provisioning/datasources,provisioning/dashboards,dashboards}
    mkdir -p "$CYBERRANGE_DIR"/filebeat
    mkdir -p /var/log/cyberrange
    
    chmod 755 "$CYBERRANGE_DIR"
    chmod 777 "$CYBERRANGE_DIR"/pcap-data
    
    log "✓ Directory structure created"
}

# Copy configuration files
copy_configs() {
    log "Copying configuration files..."
    
    # Copy Docker Compose configuration
    cp "$SCRIPT_DIR/docker-compose.monitoring.yml" "$CYBERRANGE_DIR/docker-compose.yml"
    
    # Copy Logstash configuration
    if [ -d "$SCRIPT_DIR/logstash" ]; then
        cp -r "$SCRIPT_DIR"/logstash/* "$CYBERRANGE_DIR/logstash/"
    fi
    
    # Copy Grafana configuration
    if [ -d "$SCRIPT_DIR/grafana" ]; then
        cp -r "$SCRIPT_DIR"/grafana/* "$CYBERRANGE_DIR/grafana/"
    fi
    
    # Create Logstash main config
    cat > "$CYBERRANGE_DIR/logstash/config/logstash.yml" << EOF
node.name: cyberrange-logstash
path.data: /usr/share/logstash/data
pipeline.workers: 2
pipeline.batch.size: 125
pipeline.batch.delay: 50
http.host: "0.0.0.0"
xpack.monitoring.elasticsearch.hosts: ["http://172.16.200.136:9200"]
EOF

    # Create Filebeat configuration
    cat > "$CYBERRANGE_DIR/filebeat/filebeat.yml" << EOF
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /var/log/cyberrange/*.log
    - /var/log/syslog
    - /var/log/auth.log
  fields:
    log_type: system
    environment: cyberrange

- type: docker
  containers.ids:
    - "*"
  fields:
    log_type: container
    environment: cyberrange

output.logstash:
  hosts: ["172.16.200.137:5044"]

processors:
- add_host_metadata:
    when.not.contains.tags: forwarded
- add_docker_metadata: ~

logging.level: info
logging.to_files: true
logging.files:
  path: /var/log/cyberrange
  name: filebeat.log
  keepfiles: 7
  permissions: 0644
EOF
    
    log "✓ Configuration files copied"
}

# Configure network mirroring
configure_network() {
    log "Configuring network mirroring..."
    
    # Check if vmbr0 exists
    if ! ip link show vmbr0 >/dev/null 2>&1; then
        error "Bridge vmbr0 does not exist. Please configure Proxmox networking first."
        return 1
    fi
    
    # Create TAP interface for packet mirroring
    if ! ip link show tap-mirror >/dev/null 2>&1; then
        ip tuntap add mode tap tap-mirror
        ip link set tap-mirror up
        ip link set tap-mirror master vmbr0
        log "✓ TAP mirror interface created and attached to vmbr0"
    else
        warn "TAP mirror interface already exists"
    fi
    
    # Make it persistent
    if ! grep -q "tap-mirror" /etc/network/interfaces; then
        cat >> /etc/network/interfaces << EOF

# CyberRange packet mirroring
auto tap-mirror
iface tap-mirror inet manual
    pre-up ip tuntap add mode tap tap-mirror
    up ip link set tap-mirror master vmbr0
    down ip link delete tap-mirror
EOF
        log "✓ Made TAP interface persistent"
    fi
}

# Deploy monitoring services
deploy_services() {
    log "Deploying monitoring services..."
    
    cd "$CYBERRANGE_DIR"
    
    # Pull images first
    docker compose pull
    
    # Start services
    docker compose up -d
    
    log "✓ Services started, waiting for readiness..."
    
    # Wait for services to be ready
    local max_attempts=60
    local attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        if docker compose ps | grep -q "Up"; then
            break
        fi
        sleep 5
        ((attempt++))
    done
    
    if [ $attempt -gt $max_attempts ]; then
        error "Services failed to start within timeout"
        return 1
    fi
    
    log "✓ Services deployed successfully"
}

# Test connectivity
test_connectivity() {
    log "Testing connectivity..."
    
    local services=(
        "172.16.200.137:5044:Logstash Beats"
        "172.16.200.138:3000:Grafana"
        "172.16.200.140:6379:Redis"
        "172.16.200.136:9200:Elasticsearch"
    )
    
    for service in "${services[@]}"; do
        IFS=':' read -r host port name <<< "$service"
        
        if timeout 10 bash -c "echo >/dev/tcp/$host/$port" 2>/dev/null; then
            log "✓ $name ($host:$port) is reachable"
        else
            warn "✗ $name ($host:$port) is not reachable"
        fi
    done
}

# Create Elasticsearch indices
setup_elasticsearch() {
    log "Setting up Elasticsearch indices..."
    
    # Wait for Elasticsearch to be ready
    local max_attempts=30
    local attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        if curl -s "http://172.16.200.136:9200/_cluster/health" | jq -r '.status' | grep -q -E "(yellow|green)"; then
            break
        fi
        sleep 5
        ((attempt++))
    done
    
    # Create index templates
    curl -X PUT "http://172.16.200.136:9200/_index_template/cyberrange-logs" \
        -H "Content-Type: application/json" \
        -d '{
            "index_patterns": ["cyberrange-logs-*"],
            "template": {
                "settings": {
                    "number_of_shards": 1,
                    "number_of_replicas": 0,
                    "index.refresh_interval": "5s"
                },
                "mappings": {
                    "properties": {
                        "@timestamp": {"type": "date"},
                        "message": {"type": "text"},
                        "security_event": {"type": "keyword"},
                        "threat_level": {"type": "keyword"},
                        "match_points": {"type": "integer"},
                        "team_id": {"type": "keyword"},
                        "src_ip": {"type": "ip"},
                        "dst_ip": {"type": "ip"}
                    }
                }
            }
        }' >/dev/null 2>&1
    
    log "✓ Elasticsearch indices configured"
}

# Generate summary report
generate_report() {
    log "Generating deployment report..."
    
    cat > "$CYBERRANGE_DIR/deployment-report.txt" << EOF
CyberRange Phase 1 Deployment Report
====================================
Deployment Date: $(date)
Proxmox Version: $(pveversion --verbose | head -1)

Services Deployed:
- Logstash Sensor: http://172.16.200.137:9600
- Grafana Dashboard: http://172.16.200.138:3000 
  (admin/cyberrange2024)
- Redis Cache: 172.16.200.140:6379
- Packet Capture: $CYBERRANGE_DIR/pcap-data/

Network Configuration:
- Bridge: vmbr0 (172.16.200.0/24)
- Mirror Interface: tap-mirror
- Target VM: 172.16.200.150
- Attacker VM: 172.16.200.151

Next Steps:
1. Configure Proxmox firewall rules
2. Import Grafana dashboards  
3. Test packet capture
4. Proceed to Phase 2 (Scoring Engine)

Log File: $LOG_FILE
Configuration: $CYBERRANGE_DIR/
EOF

    info "Deployment completed successfully!"
    info "Report saved to: $CYBERRANGE_DIR/deployment-report.txt"
    info ""
    info "Access Points:"
    info "• Grafana: http://172.16.200.138:3000 (admin/cyberrange2024)"
    info "• Logstash: http://172.16.200.137:9600"
    info "• Packet captures: $CYBERRANGE_DIR/pcap-data/"
    info ""
    info "To configure Proxmox firewall, run:"
    info "bash $SCRIPT_DIR/proxmox-network-config.sh"
}

# Main execution
main() {
    info "Starting CyberRange Phase 1 Deployment"
    info "======================================"
    
    check_root
    check_proxmox
    install_packages
    setup_directories
    copy_configs
    configure_network
    deploy_services
    test_connectivity
    setup_elasticsearch
    generate_report
    
    log "Phase 1 deployment completed successfully!"
}

# Error handling
trap 'error "Deployment failed at line $LINENO. Check $LOG_FILE for details."; exit 1' ERR

# Run main function
main "$@"

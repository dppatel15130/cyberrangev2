#!/bin/bash
# Prepare Offline Deployment Package for CyberRange Phase 1
# Run this script on a machine with internet access (Kali)

set -euo pipefail

# Configuration
PACKAGE_DIR="/tmp/cyberrange-offline-package"
DOCKER_IMAGES=(
    "docker.elastic.co/logstash/logstash:8.11.0"
    "grafana/grafana:10.2.0"
    "docker.elastic.co/beats/filebeat:8.11.0"
    "redis:7.2-alpine"
    "nicolaka/netshoot:v0.11"
)

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() {
    echo -e "${GREEN}[$(date +'%H:%M:%S')]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[$(date +'%H:%M:%S')] WARN:${NC} $1"
}

error() {
    echo -e "${RED}[$(date +'%H:%M:%S')] ERROR:${NC} $1"
}

info() {
    echo -e "${BLUE}[$(date +'%H:%M:%S')] INFO:${NC} $1"
}

# Create package directory
create_package_structure() {
    log "Creating offline package structure..."
    
    rm -rf "$PACKAGE_DIR"
    mkdir -p "$PACKAGE_DIR"/{docker-images,packages,scripts,configs}
    
    log "✓ Package directory created: $PACKAGE_DIR"
}

# Download required packages for offline installation
download_packages() {
    log "Downloading required packages..."
    
    cd "$PACKAGE_DIR/packages"
    
    # Create a temporary directory for package downloads
    mkdir -p apt-packages
    cd apt-packages
    
    # Download packages with dependencies
    local packages=(
        "docker.io"
        "docker-compose-plugin" 
        "bridge-utils"
        "tcpdump"
        "net-tools"
        "curl"
        "jq"
    )
    
    for package in "${packages[@]}"; do
        log "Downloading $package and dependencies..."
        apt-get download "$package" || warn "Failed to download $package"
        apt-cache depends "$package" | grep "Depends:" | cut -d':' -f2 | tr -d ' ' | xargs apt-get download 2>/dev/null || true
    done
    
    log "✓ Packages downloaded"
}

# Pull and save Docker images
download_docker_images() {
    log "Pulling and saving Docker images..."
    
    cd "$PACKAGE_DIR/docker-images"
    
    for image in "${DOCKER_IMAGES[@]}"; do
        log "Pulling $image..."
        if docker pull "$image"; then
            local filename=$(echo "$image" | tr '/' '_' | tr ':' '_')
            log "Saving $image as ${filename}.tar..."
            docker save "$image" -o "${filename}.tar"
        else
            warn "Failed to pull $image"
        fi
    done
    
    log "✓ Docker images saved"
}

# Copy configuration files
copy_configurations() {
    log "Copying configuration files..."
    
    local source_dir="/home/kali/Downloads/cyberrangev1-main/infrastructure"
    
    # Copy all configuration files
    cp -r "$source_dir"/* "$PACKAGE_DIR/configs/" || true
    
    # Remove the prepare script from configs to avoid confusion
    rm -f "$PACKAGE_DIR/configs/prepare-offline-package.sh"
    
    log "✓ Configuration files copied"
}

# Create modified Docker Compose for offline deployment
create_offline_docker_compose() {
    log "Creating offline Docker Compose configuration..."
    
    cat > "$PACKAGE_DIR/configs/docker-compose.offline.yml" << 'EOF'
version: '3.8'

services:
  # Logstash sensor for network traffic analysis
  logstash-sensor:
    image: logstash:8.11.0
    container_name: cyberrange-logstash
    hostname: logstash-sensor
    environment:
      - "LS_JAVA_OPTS=-Xmx512m -Xms512m"
      - "ELASTICSEARCH_HOSTS=http://172.16.200.136:9200"
    volumes:
      - ./logstash/config:/usr/share/logstash/config:ro
      - ./logstash/pipeline:/usr/share/logstash/pipeline:ro
      - ./logstash/patterns:/usr/share/logstash/patterns:ro
      - logstash-data:/usr/share/logstash/data
      - /var/log/cyberrange:/var/log/cyberrange:rw
    ports:
      - "5044:5044"
      - "5000:5000/tcp"
      - "5000:5000/udp"
      - "9600:9600"
    networks:
      cyberrange:
        ipv4_address: 172.16.200.137
    restart: unless-stopped

  # Simple packet capture using tcpdump (no external image needed)
  packet-capture:
    image: netshoot:v0.11
    container_name: cyberrange-pcap
    hostname: packet-capture
    privileged: true
    network_mode: host
    volumes:
      - ./pcap-data:/pcap:rw
    command: >
      sh -c "
        echo 'Starting packet capture...';
        while true; do
          if ip link show tap-mirror >/dev/null 2>&1; then
            tcpdump -i tap-mirror -w /pcap/cyberrange-$(date +%Y%m%d-%H%M%S).pcap -G 3600 -W 24 -Z root;
          else
            echo 'Waiting for tap-mirror interface...';
            sleep 30;
          fi
        done
      "
    restart: unless-stopped

  # Grafana for monitoring
  grafana:
    image: grafana:10.2.0
    container_name: cyberrange-grafana
    hostname: grafana
    environment:
      - GF_SECURITY_ADMIN_USER=admin
      - GF_SECURITY_ADMIN_PASSWORD=cyberrange2024
      - GF_USERS_ALLOW_SIGN_UP=false
      - GF_INSTALL_PLUGINS=
      - GF_SECURITY_ALLOW_EMBEDDING=true
      - GF_AUTH_ANONYMOUS_ENABLED=true
      - GF_AUTH_ANONYMOUS_ORG_ROLE=Viewer
    volumes:
      - grafana-data:/var/lib/grafana
      - ./grafana/provisioning:/etc/grafana/provisioning:ro
    ports:
      - "3000:3000"
    networks:
      cyberrange:
        ipv4_address: 172.16.200.138
    restart: unless-stopped

  # Redis for caching
  redis:
    image: redis:7.2-alpine
    container_name: cyberrange-redis
    hostname: redis
    command: redis-server --appendonly yes --requirepass cyberrange2024
    volumes:
      - redis-data:/data
    ports:
      - "6379:6379"
    networks:
      cyberrange:
        ipv4_address: 172.16.200.140
    restart: unless-stopped

volumes:
  logstash-data:
  grafana-data:
  redis-data:

networks:
  cyberrange:
    driver: bridge
    ipam:
      config:
        - subnet: 172.16.200.0/24
          gateway: 172.16.200.1
EOF

    log "✓ Offline Docker Compose configuration created"
}

# Create offline deployment script
create_offline_deployment_script() {
    log "Creating offline deployment script..."
    
    cat > "$PACKAGE_DIR/scripts/deploy-offline.sh" << 'EOF'
#!/bin/bash
# Offline Deployment Script for CyberRange Phase 1
# Run this script on the Proxmox host (no internet required)

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PACKAGE_DIR="$(dirname "$SCRIPT_DIR")"
CYBERRANGE_DIR="/opt/cyberrange"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log() { echo -e "${GREEN}[$(date +'%H:%M:%S')]${NC} $1"; }
warn() { echo -e "${YELLOW}[$(date +'%H:%M:%S')] WARN:${NC} $1"; }
error() { echo -e "${RED}[$(date +'%H:%M:%S')] ERROR:${NC} $1"; }

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    error "This script must be run as root"
    exit 1
fi

# Install packages from local files
install_offline_packages() {
    log "Installing packages from local files..."
    
    cd "$PACKAGE_DIR/packages/apt-packages"
    
    # Install all .deb files
    if ls *.deb >/dev/null 2>&1; then
        dpkg -i *.deb || true
        apt-get install -f -y  # Fix any dependency issues
        systemctl enable docker || true
        systemctl start docker || true
    else
        warn "No .deb packages found, assuming packages are already installed"
    fi
    
    log "✓ Packages installed"
}

# Load Docker images from saved files
load_docker_images() {
    log "Loading Docker images from saved files..."
    
    cd "$PACKAGE_DIR/docker-images"
    
    for tarfile in *.tar; do
        if [ -f "$tarfile" ]; then
            log "Loading $tarfile..."
            docker load -i "$tarfile"
        fi
    done
    
    # Tag images to remove registry prefixes
    docker tag docker.elastic.co/logstash/logstash:8.11.0 logstash:8.11.0 2>/dev/null || true
    docker tag grafana/grafana:10.2.0 grafana:10.2.0 2>/dev/null || true
    docker tag nicolaka/netshoot:v0.11 netshoot:v0.11 2>/dev/null || true
    
    log "✓ Docker images loaded and tagged"
}

# Setup directories and configurations
setup_environment() {
    log "Setting up environment..."
    
    # Create directories
    mkdir -p "$CYBERRANGE_DIR"/{logs,pcap-data,backups}
    mkdir -p /var/log/cyberrange
    
    # Copy configurations
    cp -r "$PACKAGE_DIR/configs"/* "$CYBERRANGE_DIR/"
    
    # Use offline Docker Compose
    cp "$CYBERRANGE_DIR/docker-compose.offline.yml" "$CYBERRANGE_DIR/docker-compose.yml"
    
    # Create basic Logstash configuration
    mkdir -p "$CYBERRANGE_DIR/logstash"/{config,pipeline}
    
    cat > "$CYBERRANGE_DIR/logstash/config/logstash.yml" << 'EOFLOG'
node.name: cyberrange-logstash
path.data: /usr/share/logstash/data
http.host: "0.0.0.0"
EOFLOG

    # Create simplified pipeline for offline mode
    cat > "$CYBERRANGE_DIR/logstash/pipeline/cyberrange.conf" << 'EOFPIPE'
input {
  tcp {
    port => 5000
    codec => json_lines
  }
  
  udp {
    port => 5000
    codec => json_lines
  }
}

filter {
  mutate {
    add_field => { "cyberrange_environment" => "offline_mode" }
  }
}

output {
  # Store locally if Elasticsearch is not available
  file {
    path => "/var/log/cyberrange/logstash-output-%{+YYYY.MM.dd}.log"
    codec => json_lines
  }
  
  # Try to send to Elasticsearch if available
  elasticsearch {
    hosts => ["172.16.200.136:9200"]
    index => "cyberrange-logs-%{+YYYY.MM.dd}"
  }
  
  stdout { codec => rubydebug }
}
EOFPIPE

    chmod 755 "$CYBERRANGE_DIR"
    chmod 777 "$CYBERRANGE_DIR/pcap-data"
    
    log "✓ Environment setup completed"
}

# Configure network
configure_network() {
    log "Configuring network mirroring..."
    
    # Create TAP interface for packet mirroring
    if ! ip link show tap-mirror >/dev/null 2>&1; then
        ip tuntap add mode tap tap-mirror
        ip link set tap-mirror up
        
        # Attach to vmbr0 if it exists
        if ip link show vmbr0 >/dev/null 2>&1; then
            ip link set tap-mirror master vmbr0
            log "✓ TAP interface attached to vmbr0"
        else
            warn "vmbr0 not found, tap-mirror created but not attached"
        fi
    else
        log "✓ TAP interface already exists"
    fi
}

# Deploy services
deploy_services() {
    log "Deploying services..."
    
    cd "$CYBERRANGE_DIR"
    
    # Start services
    docker compose up -d
    
    # Wait for services
    sleep 10
    
    log "✓ Services deployed"
}

# Test deployment
test_deployment() {
    log "Testing deployment..."
    
    local success=0
    local total=0
    
    # Test Docker containers
    for container in cyberrange-grafana cyberrange-redis cyberrange-logstash; do
        ((total++))
        if docker ps | grep -q "$container.*Up"; then
            log "✓ $container is running"
            ((success++))
        else
            warn "✗ $container is not running"
        fi
    done
    
    # Test network interfaces
    ((total++))
    if ip link show tap-mirror >/dev/null 2>&1; then
        log "✓ TAP mirror interface exists"
        ((success++))
    else
        warn "✗ TAP mirror interface not found"
    fi
    
    log "Deployment test: $success/$total services operational"
    
    if [ $success -gt $((total / 2)) ]; then
        log "✓ Offline deployment completed successfully!"
        echo ""
        echo "Access URLs (if network is configured):"
        echo "• Grafana: http://172.16.200.138:3000 (admin/cyberrange2024)"
        echo "• Logstash: http://172.16.200.137:9600"
        echo "• Logs: /var/log/cyberrange/"
        echo "• Packet captures: $CYBERRANGE_DIR/pcap-data/"
    else
        error "Deployment has issues, check logs"
        return 1
    fi
}

# Main execution
main() {
    log "Starting offline CyberRange deployment..."
    
    install_offline_packages
    load_docker_images
    setup_environment
    configure_network
    deploy_services
    test_deployment
    
    log "Offline deployment completed!"
}

main "$@"
EOF

    chmod +x "$PACKAGE_DIR/scripts/deploy-offline.sh"
    
    log "✓ Offline deployment script created"
}

# Create simplified Grafana datasources for offline mode
create_offline_grafana_config() {
    log "Creating offline Grafana configuration..."
    
    mkdir -p "$PACKAGE_DIR/configs/grafana/provisioning/datasources"
    
    cat > "$PACKAGE_DIR/configs/grafana/provisioning/datasources/datasources.yml" << 'EOF'
apiVersion: 1

datasources:
  # Local file datasource (for offline mode)
  - name: Local-Logs
    type: file
    access: proxy
    url: file:///var/log/cyberrange/
    isDefault: true

  # Redis datasource (if available)
  - name: Redis-CyberRange
    type: redis-datasource
    access: proxy
    url: redis://172.16.200.140:6379
    jsonData:
      client: standalone
      timeout: 10
    secureJsonData:
      password: cyberrange2024

  # Try Elasticsearch (may not be available offline)
  - name: Elasticsearch-CyberRange
    type: elasticsearch
    access: proxy
    url: http://172.16.200.136:9200
    database: "cyberrange-logs-*"
    basicAuth: false
    jsonData:
      interval: "Daily"
      timeField: "@timestamp"
      esVersion: 8
EOF

    log "✓ Offline Grafana configuration created"
}

# Create transfer instructions
create_transfer_instructions() {
    log "Creating transfer instructions..."
    
    cat > "$PACKAGE_DIR/TRANSFER-INSTRUCTIONS.txt" << EOF
CyberRange Offline Deployment Package
====================================

This package contains everything needed to deploy CyberRange Phase 1 
on an air-gapped Proxmox host without internet access.

Package Contents:
- docker-images/     Docker container images (*.tar files)
- packages/          Debian packages for offline installation
- configs/           Configuration files for all services
- scripts/           Deployment scripts

Transfer Methods:
=================

Method 1: SCP Transfer (if network access to Proxmox)
-----------------------------------------------------
From Kali machine:
scp -r $PACKAGE_DIR root@172.16.200.129:/tmp/cyberrange-package

Method 2: USB Transfer (if completely air-gapped)
-------------------------------------------------
1. Copy entire package to USB drive:
   cp -r $PACKAGE_DIR /media/usb/

2. On Proxmox host, mount USB and copy:
   mkdir -p /tmp/cyberrange-package
   cp -r /media/usb/cyberrange-offline-package/* /tmp/cyberrange-package/

Method 3: Direct File Copy
--------------------------
Use any file transfer method available in your environment.

Deployment on Proxmox Host:
===========================

1. Ensure you are root user
2. Navigate to the package directory:
   cd /tmp/cyberrange-package
   
3. Run the offline deployment script:
   bash scripts/deploy-offline.sh

4. Verify deployment:
   docker ps
   ip link show tap-mirror

Expected Results:
- Grafana available at: http://172.16.200.138:3000
- Logstash monitoring at: http://172.16.200.137:9600  
- Redis cache at: 172.16.200.140:6379
- Packet capture in: /opt/cyberrange/pcap-data/

Package Size: $(du -sh $PACKAGE_DIR | cut -f1)
Created: $(date)
EOF

    log "✓ Transfer instructions created"
}

# Create package archive
create_package_archive() {
    log "Creating package archive..."
    
    cd "$(dirname "$PACKAGE_DIR")"
    local archive_name="cyberrange-offline-$(date +%Y%m%d-%H%M%S).tar.gz"
    
    tar -czf "$archive_name" "$(basename "$PACKAGE_DIR")"
    
    log "✓ Package archive created: $(pwd)/$archive_name"
    log "✓ Archive size: $(du -sh "$archive_name" | cut -f1)"
    
    echo ""
    info "Offline package preparation completed!"
    info "Archive: $(pwd)/$archive_name"
    info "Directory: $PACKAGE_DIR"
    info ""
    info "Next steps:"
    info "1. Transfer the package to Proxmox host using SCP or USB"
    info "2. Extract: tar -xzf $archive_name"  
    info "3. Deploy: bash cyberrange-offline-package/scripts/deploy-offline.sh"
}

# Main execution
main() {
    info "Preparing CyberRange offline deployment package..."
    info "This will download Docker images and packages for air-gapped deployment"
    echo ""
    
    create_package_structure
    download_packages
    download_docker_images
    copy_configurations
    create_offline_docker_compose
    create_offline_deployment_script
    create_offline_grafana_config
    create_transfer_instructions
    create_package_archive
    
    log "Offline package preparation completed successfully!"
}

# Check if Docker is available
if ! command -v docker >/dev/null 2>&1; then
    error "Docker is not installed. Please install Docker first."
    exit 1
fi

# Run main function
main "$@"

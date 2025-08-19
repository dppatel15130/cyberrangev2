#!/bin/bash

# CyberRange Platform Startup Script
# This script starts the complete cyber warfare platform

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
BACKEND_DIR="./backend"
FRONTEND_DIR="./frontend"
ENV_FILE="./environment.config"

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "${PURPLE}$1${NC}"
}

# Check if running as root (needed for some operations)
check_permissions() {
    if [[ $EUID -eq 0 ]]; then
        print_warning "Running as root. Some operations may require different permissions."
    fi
}

# Check system requirements
check_requirements() {
    print_header "🔍 Checking System Requirements..."
    
    # Check Node.js
    if command -v node &> /dev/null; then
        NODE_VERSION=$(node --version)
        print_success "Node.js detected: $NODE_VERSION"
    else
        print_error "Node.js is not installed. Please install Node.js 16+ to continue."
        exit 1
    fi
    
    # Check npm
    if command -v npm &> /dev/null; then
        NPM_VERSION=$(npm --version)
        print_success "npm detected: $NPM_VERSION"
    else
        print_error "npm is not installed. Please install npm to continue."
        exit 1
    fi
    
    # Check MySQL
    if command -v mysql &> /dev/null; then
        print_success "MySQL client detected"
    else
        print_warning "MySQL client not found. Database operations may fail."
    fi
    
    # Check if MySQL server is running
    if systemctl is-active --quiet mysql || systemctl is-active --quiet mariadb; then
        print_success "MySQL/MariaDB service is running"
    else
        print_warning "MySQL/MariaDB service may not be running"
    fi
    
    # Check for curl (needed for API calls)
    if command -v curl &> /dev/null; then
        print_success "curl detected"
    else
        print_warning "curl not found. Some external service checks may fail."
    fi
}

# Setup environment
setup_environment() {
    print_header "🔧 Setting up Environment..."
    
    # Copy environment configuration if .env doesn't exist
    if [ -f "$ENV_FILE" ]; then
        if [ ! -f "$BACKEND_DIR/.env" ]; then
            print_status "Copying environment configuration..."
            cp "$ENV_FILE" "$BACKEND_DIR/.env"
            print_success "Environment configuration copied to backend"
        fi
    else
        print_warning "Environment configuration file not found. Using defaults."
    fi
    
    # Create required directories
    print_status "Creating required directories..."
    sudo mkdir -p /opt/cyberrange/pcap-data
    sudo mkdir -p /var/log/cyberrange
    sudo chown -R $USER:$USER /opt/cyberrange 2>/dev/null || true
    sudo chown -R $USER:$USER /var/log/cyberrange 2>/dev/null || true
    print_success "Directories created"
}

# Install dependencies
install_dependencies() {
    print_header "📦 Installing Dependencies..."
    
    # Backend dependencies
    print_status "Installing backend dependencies..."
    cd "$BACKEND_DIR"
    if npm install; then
        print_success "Backend dependencies installed"
    else
        print_error "Failed to install backend dependencies"
        exit 1
    fi
    cd ..
    
    # Frontend dependencies
    print_status "Installing frontend dependencies..."
    cd "$FRONTEND_DIR"
    if npm install; then
        print_success "Frontend dependencies installed"
    else
        print_error "Failed to install frontend dependencies"
        exit 1
    fi
    cd ..
}

# Initialize database
initialize_database() {
    print_header "🗄️  Initializing Database..."
    
    cd "$BACKEND_DIR"
    if node scripts/initializeDatabase.js; then
        print_success "Database initialized successfully"
    else
        print_error "Database initialization failed"
        exit 1
    fi
    cd ..
}

# Check external services
check_external_services() {
    print_header "🌐 Checking External Services..."
    
    # Check Proxmox API
    PROXMOX_URL="https://172.16.200.129:8006"
    print_status "Checking Proxmox API at $PROXMOX_URL..."
    if curl -s -k --connect-timeout 5 "$PROXMOX_URL" >/dev/null 2>&1; then
        print_success "Proxmox API accessible"
    else
        print_warning "Proxmox API not accessible. VM management will be limited."
    fi
    
    # Check Guacamole
    GUACAMOLE_URL="http://172.16.200.129:8080/guacamole"
    print_status "Checking Guacamole at $GUACAMOLE_URL..."
    if curl -s --connect-timeout 5 "$GUACAMOLE_URL" >/dev/null 2>&1; then
        print_success "Guacamole accessible"
    else
        print_warning "Guacamole not accessible. Remote desktop features will be limited."
    fi
    
    # Check ELK Stack
    ELK_URL="http://172.16.200.136:9200"
    print_status "Checking Elasticsearch at $ELK_URL..."
    if curl -s --connect-timeout 5 "$ELK_URL/_cluster/health" >/dev/null 2>&1; then
        print_success "Elasticsearch accessible"
    else
        print_warning "Elasticsearch not accessible. Advanced analytics will be limited."
    fi
    
    # Check Kibana
    KIBANA_URL="http://172.16.200.136:5601"
    print_status "Checking Kibana at $KIBANA_URL..."
    if curl -s --connect-timeout 5 "$KIBANA_URL/api/status" >/dev/null 2>&1; then
        print_success "Kibana accessible"
    else
        print_warning "Kibana not accessible. Dashboard features will be limited."
    fi
}

# Start services
start_services() {
    print_header "🚀 Starting CyberRange Services..."
    
    # Start backend
    print_status "Starting backend server..."
    cd "$BACKEND_DIR"
    npm start &
    BACKEND_PID=$!
    cd ..
    
    # Wait a moment for backend to start
    sleep 3
    
    # Check if backend started successfully
    if ps -p $BACKEND_PID > /dev/null; then
        print_success "Backend server started (PID: $BACKEND_PID)"
    else
        print_error "Backend server failed to start"
        exit 1
    fi
    
    # Start frontend
    print_status "Starting frontend development server..."
    cd "$FRONTEND_DIR"
    npm run dev &
    FRONTEND_PID=$!
    cd ..
    
    # Wait for frontend to start
    sleep 5
    
    # Check if frontend started successfully
    if ps -p $FRONTEND_PID > /dev/null; then
        print_success "Frontend server started (PID: $FRONTEND_PID)"
    else
        print_error "Frontend server failed to start"
        kill $BACKEND_PID 2>/dev/null
        exit 1
    fi
    
    # Save PIDs for cleanup
    echo $BACKEND_PID > .backend.pid
    echo $FRONTEND_PID > .frontend.pid
}

# Display access information
show_access_info() {
    print_header "🎯 CyberRange Platform Access Information"
    echo ""
    print_success "Frontend Application: http://localhost:5173"
    print_success "Backend API: http://localhost:5000"
    print_success "API Health Check: http://localhost:5000/api/health"
    echo ""
    print_header "🔐 Default Admin Credentials:"
    echo -e "${YELLOW}Username: admin${NC}"
    echo -e "${YELLOW}Password: admin123${NC}"
    echo -e "${RED}⚠️  Please change the password after first login!${NC}"
    echo ""
    print_header "📊 External Services:"
    echo -e "${CYAN}Proxmox VE: https://172.16.200.129:8006${NC}"
    echo -e "${CYAN}Guacamole: http://172.16.200.129:8080/guacamole${NC}"
    echo -e "${CYAN}Kibana: http://172.16.200.136:5601${NC}"
    echo ""
    print_header "🛠️  Management Commands:"
    echo -e "${CYAN}Stop Services: ./stop-cyberrange.sh${NC}"
    echo -e "${CYAN}View Logs: tail -f backend/logs/*.log${NC}"
    echo -e "${CYAN}Database Reset: node backend/scripts/initializeDatabase.js${NC}"
}

# Cleanup function
cleanup() {
    print_header "🧹 Cleaning up..."
    
    if [ -f .backend.pid ]; then
        BACKEND_PID=$(cat .backend.pid)
        if ps -p $BACKEND_PID > /dev/null; then
            kill $BACKEND_PID
            print_status "Backend server stopped"
        fi
        rm .backend.pid
    fi
    
    if [ -f .frontend.pid ]; then
        FRONTEND_PID=$(cat .frontend.pid)
        if ps -p $FRONTEND_PID > /dev/null; then
            kill $FRONTEND_PID
            print_status "Frontend server stopped"
        fi
        rm .frontend.pid
    fi
}

# Handle Ctrl+C
trap cleanup EXIT INT TERM

# Main execution
main() {
    clear
    print_header "================================================="
    print_header "🛡️  CyberRange Cyber Warfare Platform Startup"
    print_header "================================================="
    echo ""
    
    check_permissions
    check_requirements
    setup_environment
    
    # Ask user what to do
    echo ""
    print_header "🎮 Startup Options:"
    echo "1) Full setup (install dependencies + initialize database + start services)"
    echo "2) Quick start (start services only)"
    echo "3) Database setup only"
    echo "4) Check external services only"
    echo ""
    read -p "Select option (1-4): " choice
    
    case $choice in
        1)
            install_dependencies
            initialize_database
            check_external_services
            start_services
            show_access_info
            ;;
        2)
            check_external_services
            start_services
            show_access_info
            ;;
        3)
            initialize_database
            ;;
        4)
            check_external_services
            ;;
        *)
            print_error "Invalid option"
            exit 1
            ;;
    esac
    
    if [ "$choice" == "1" ] || [ "$choice" == "2" ]; then
        print_header "🎉 CyberRange Platform is now running!"
        print_status "Press Ctrl+C to stop all services"
        
        # Keep script running and monitor services
        while true; do
            sleep 10
            
            # Check if services are still running
            if [ -f .backend.pid ]; then
                BACKEND_PID=$(cat .backend.pid)
                if ! ps -p $BACKEND_PID > /dev/null; then
                    print_error "Backend server stopped unexpectedly"
                    break
                fi
            fi
            
            if [ -f .frontend.pid ]; then
                FRONTEND_PID=$(cat .frontend.pid)
                if ! ps -p $FRONTEND_PID > /dev/null; then
                    print_error "Frontend server stopped unexpectedly"
                    break
                fi
            fi
        done
    fi
}

# Create stop script
create_stop_script() {
    cat > stop-cyberrange.sh << 'EOF'
#!/bin/bash

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_status "Stopping CyberRange services..."

# Stop services using PID files
if [ -f .backend.pid ]; then
    BACKEND_PID=$(cat .backend.pid)
    if ps -p $BACKEND_PID > /dev/null; then
        kill $BACKEND_PID
        print_success "Backend server stopped"
    fi
    rm .backend.pid
fi

if [ -f .frontend.pid ]; then
    FRONTEND_PID=$(cat .frontend.pid)
    if ps -p $FRONTEND_PID > /dev/null; then
        kill $FRONTEND_PID
        print_success "Frontend server stopped"
    fi
    rm .frontend.pid
fi

# Kill any remaining Node.js processes related to the project
pkill -f "node.*server.js" 2>/dev/null || true
pkill -f "npm.*start" 2>/dev/null || true
pkill -f "npm.*dev" 2>/dev/null || true

print_success "All CyberRange services stopped"
EOF
    chmod +x stop-cyberrange.sh
}

# Create the stop script
create_stop_script

# Run main function
main "$@"

# 🛡️ CyberRange Cyber Warfare Platform

A comprehensive cyber warfare competition platform designed for red team vs blue team exercises, capture-the-flag competitions, and cybersecurity training in air-gapped environments.

## 🌟 Features

### Core Platform Features
- **Real-time Cyber Warfare Competitions** - Dynamic attack/defense scenarios
- **Automatic Vulnerability Detection** - AI-powered exploit detection without manual flag entry
- **Decreasing Point System** - Points decay as more teams find the same vulnerability
- **Team Management** - Complete team creation, joining, and member management
- **Real-time Scoring** - WebSocket-based live scoring and event broadcasting
- **VM Management** - Automated Proxmox VM deployment and management
- **Admin Dashboard** - Comprehensive real-time monitoring and analytics

### Advanced Features
- **Air-gapped Operation** - No internet dependencies
- **ELK Stack Integration** - Advanced log analysis with Elasticsearch, Logstash, and Kibana
- **Packet Capture Analysis** - Automated network traffic analysis for attack detection
- **Guacamole Integration** - Web-based remote desktop access to VMs
- **Multiple Match Types** - Attack/Defense, CTF, Red vs Blue, Free-for-all
- **Vulnerability Signature Detection** - Automated detection of common exploits

## 🏗️ Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Frontend      │    │     Backend      │    │   External      │
│   (React)       │    │   (Node.js)      │    │   Services      │
│                 │    │                  │    │                 │
│ • Admin Dashboard│◄──►│ • Game Engine    │◄──►│ • Proxmox VE    │
│ • Match View    │    │ • Scoring System │    │ • Guacamole     │
│ • Team Mgmt     │    │ • Vuln Detection │    │ • ELK Stack     │
│ • Real-time UI  │    │ • WebSocket API  │    │ • MySQL DB      │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

## 🚀 Quick Start

### Prerequisites
- **Operating System**: Kali Linux or Ubuntu 20.04+
- **Node.js**: 16.x or higher
- **MySQL**: 8.0 or higher
- **Proxmox VE**: 7.x with API access
- **RAM**: 8GB minimum, 16GB recommended
- **Storage**: 100GB+ for VM templates and logs

### Installation & Setup

1. **Clone and Navigate**
   ```bash
   cd /home/kali/Downloads/cyberrangev1-main
   ```

2. **Run Automated Setup**
   ```bash
   ./start-cyberrange.sh
   ```
   
   Choose option 1 for full setup including:
   - Dependency installation
   - Database initialization
   - Service startup
   - External service checks

3. **Access the Platform**
   - **Frontend**: http://localhost:5173
   - **Backend API**: http://localhost:5000
   - **Admin Credentials**: admin / admin123

## 🔧 Configuration

### Environment Variables

The platform uses environment variables defined in `environment.config`:

```bash
# Core Configuration
NODE_ENV=development
PORT=5000
JWT_SECRET=cyberrange_super_secret_key_2024

# Database
DB_HOST=127.0.0.1
DB_NAME=cyberrangev3
DB_USER=root
DB_PASSWORD=kali

# Proxmox VE
PROXMOX_API_URL=https://172.16.200.129:8006
PROXMOX_API_TOKEN_NAME=cyberrange@pve!ansible
PROXMOX_API_TOKEN_VALUE=9d14390f-b94b-4012-bef5-699670e81cfa

# ELK Stack
ELASTICSEARCH_URL=http://172.16.200.136:9200
KIBANA_URL=http://172.16.200.136:5601

# Features
ENABLE_AUTO_SCORING=true
ENABLE_PACKET_ANALYSIS=true
SCORING_DECAY_ENABLED=true
```

### VM Configuration

The platform is pre-configured for the following VMs:
- **VM 103**: Windows 7 SP1 x64 (Vulnerable Target)
- **VM 104**: Kali Linux 2024.2 (Attacker Workstation)

## 🎮 Usage Guide

### For Administrators

1. **Create a Match**
   - Navigate to Admin Dashboard
   - Click "Create Match"
   - Configure match parameters:
     - Name and description
     - Match type (Attack/Defense, CTF, etc.)
     - Duration and team limits
     - Enable auto-scoring and packet capture

2. **Manage Teams**
   - Teams can be created by users or admins
   - Set team size limits and network segments
   - Monitor team performance in real-time

3. **Monitor Matches**
   - Real-time scoreboard updates
   - Vulnerability detection alerts
   - Network activity monitoring
   - ELK stack analytics (if available)

### For Participants

1. **Join/Create a Team**
   - Register an account
   - Create a new team or join existing
   - Wait for match assignment

2. **Access VMs**
   - VMs are automatically assigned when match starts
   - Use Guacamole for web-based remote access
   - Or connect directly via RDP/SSH

3. **Compete**
   - Find and exploit vulnerabilities
   - Points awarded automatically for successful exploits
   - Monitor team ranking on live scoreboard

## 🏆 Scoring System

### Automatic Vulnerability Detection

The platform automatically detects and scores the following:

| Vulnerability Type | Base Points | Detection Method |
|-------------------|-------------|------------------|
| MS17-010 (EternalBlue) | 150 | Network + Process |
| MS08-067 (Conficker) | 120 | Network Analysis |
| BlueKeep RDP | 140 | Packet Capture |
| Weak Passwords | 80 | Auth Logs |
| Privilege Escalation | 130 | System Logs |
| Web Exploitation | 90 | HTTP Analysis |
| Lateral Movement | 110 | Network Flow |
| Data Exfiltration | 160 | File Access |

### Point Decay System

- **First Blood Bonus**: +50 points for first team to find vulnerability
- **Decay Rate**: Points decrease by 50% for each additional team
- **Minimum Points**: 10 points (always worth something)

### Example Scoring Progression
- Team 1 finds MS17-010: 150 + 50 = **200 points**
- Team 2 finds MS17-010: 150 × 0.5 = **75 points**
- Team 3 finds MS17-010: 75 × 0.5 = **37 points**
- Team 4 finds MS17-010: 37 × 0.5 = **18 points**

## 🔍 Vulnerability Detection Methods

### 1. Network Traffic Analysis
- Packet capture via tcpdump/tshark
- Protocol analysis for attack patterns
- Port scanning detection
- SMB exploit signatures

### 2. System Log Analysis
- Authentication attempts
- Process execution
- File access patterns
- Privilege escalation events

### 3. ELK Stack Integration (Optional)
- Elasticsearch for log storage
- Logstash for log processing
- Kibana for visualization
- Real-time security event correlation

### 4. Process Monitoring
- Metasploit framework detection
- Credential cracking tools
- Enumeration tool usage

## 🌐 External Service Integration

### Proxmox VE
- **Purpose**: VM management and deployment
- **Requirements**: API token with VM start/stop permissions
- **Features**: Automatic VM assignment, power management, status monitoring

### Apache Guacamole
- **Purpose**: Web-based remote desktop access
- **Requirements**: Running Guacamole server with database
- **Features**: Browser-based RDP/SSH access to competition VMs

### ELK Stack (Optional)
- **Purpose**: Advanced log analysis and visualization
- **Components**: Elasticsearch, Logstash, Kibana
- **Features**: Real-time log correlation, attack visualization, forensic analysis

## 📊 Admin Dashboard Features

### Real-time Monitoring
- Active match status
- Team performance metrics
- Vulnerability discovery timeline
- System health monitoring

### Analytics
- Scoring trend analysis
- Vulnerability type distribution
- Team performance comparison
- Attack pattern visualization

### Management
- Match creation and control
- Team management
- VM assignment and monitoring
- System configuration

## 🔒 Security Considerations

### Air-gapped Operation
- No internet dependencies
- Local package repositories
- Offline vulnerability databases
- Self-contained operation

### Network Isolation
- Team-based network segmentation
- Traffic capture and analysis
- Controlled VM communication
- Secure admin interfaces

## 🛠️ Development & Customization

### Project Structure
```
cyberrangev1-main/
├── backend/                 # Node.js API server
│   ├── config/             # Database and logging config
│   ├── controllers/        # API route controllers
│   ├── models/            # Database models
│   ├── services/          # Core platform services
│   ├── routes/            # API routes
│   └── scripts/           # Utility scripts
├── frontend/              # React.js web application
│   ├── src/
│   │   ├── components/    # React components
│   │   ├── pages/         # Application pages
│   │   ├── services/      # API client services
│   │   └── hooks/         # Custom React hooks
├── infrastructure/        # Deployment and monitoring
└── deployment/           # VM deployment guides
```

### Adding New Vulnerability Signatures

1. Edit `backend/services/vulnerabilityDetectionService.js`
2. Add new signature to `initializeVulnerabilitySignatures()`
3. Configure detection patterns and point values
4. Test with simulated exploitation

### Custom Scoring Rules

1. Modify `backend/models/Match.js` for default scoring rules
2. Update `scoringService.js` for custom point calculations
3. Adjust frontend scoring displays

## 📝 Logs & Troubleshooting

### Log Locations
- **Application Logs**: `/var/log/cyberrange/app.log`
- **Security Logs**: `/var/log/cyberrange/security.log`
- **Packet Captures**: `/opt/cyberrange/pcap-data/`
- **ELK Logs**: Elasticsearch indices `cyberrange-*`

### Common Issues

1. **Database Connection Failed**
   ```bash
   # Check MySQL service
   sudo systemctl status mysql
   
   # Reset database
   node backend/scripts/initializeDatabase.js
   ```

2. **Proxmox API Not Accessible**
   ```bash
   # Test API connectivity
   curl -k https://172.16.200.129:8006/api2/json/version
   
   # Verify token permissions
   ```

3. **ELK Stack Unavailable**
   ```bash
   # Check Elasticsearch
   curl http://172.16.200.136:9200/_cluster/health
   
   # Platform continues without ELK if unavailable
   ```

## 🤝 Contributing

### Development Setup
1. Fork the repository
2. Create feature branch
3. Follow existing code patterns
4. Test thoroughly in development environment
5. Submit pull request

### Code Standards
- **Backend**: Node.js with Express, Sequelize ORM
- **Frontend**: React with Bootstrap, Chart.js
- **Database**: MySQL with proper indexing
- **API**: RESTful design with WebSocket events

## 📄 License

This project is developed for educational and training purposes in cybersecurity environments.

## 🆘 Support

For issues and questions:
1. Check logs in `/var/log/cyberrange/`
2. Review this documentation
3. Verify external service connectivity
4. Test with minimal configuration

---

**⚠️ Important Security Notice**: This platform contains intentionally vulnerable systems for training purposes. Only deploy in isolated, controlled environments. Never expose to production networks or the internet.

**🎯 Happy Hacking!** - Use this platform responsibly for cybersecurity education and training.

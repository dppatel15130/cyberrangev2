# CyberRange Phase 2: Real-Time Cyber-Warfare Competition Platform

## Overview

Phase 2 transforms the CyberRange platform into a dynamic cyber-warfare competition system with real-time scoring, team management, and automated attack detection - all designed to run in air-gapped environments.

## 🚀 New Features

### 1. Dynamic Match System
- **Match Types**: Attack/Defense, King of the Hill, Capture the Flag
- **Flexible Configuration**: Network isolation, VM templates, scoring rules
- **Real-Time Management**: Start, stop, and monitor matches dynamically
- **Automated Infrastructure**: VM deployment and network segmentation

### 2. Team Management
- **Team Creation**: Users can create and join teams
- **Member Management**: Add/remove members, role assignments
- **Performance Tracking**: Team statistics and achievements
- **Multi-Team Competitions**: Support for large-scale tournaments

### 3. Real-Time Scoring Engine
- **Automated Detection**: Network packet analysis for attack patterns
- **Multiple Data Sources**: PCAP files, system logs, ELK stack integration
- **Attack Recognition**: Port scanning, brute force, web exploits, lateral movement
- **Confidence Scoring**: AI-powered confidence levels for automated events
- **Manual Scoring**: Admin override capabilities

### 4. WebSocket Integration
- **Live Updates**: Real-time scoreboard and event feeds
- **Match Monitoring**: Live team performance and network activity
- **Event Broadcasting**: Instant notifications for scoring events
- **Dashboard Integration**: Dynamic charts and statistics

### 5. Air-Gapped Operation
- **Offline Deployment**: No internet dependencies
- **Local Analysis**: Built-in packet capture and log processing
- **Proxmox Integration**: Direct VM and network management
- **Fallback Systems**: Graceful degradation when tools unavailable

## 🏗️ Architecture

### Backend Services

#### 1. Game Engine (`services/gameEngine.js`)
```javascript
// Core match management
- Match lifecycle (create, start, stop)
- VM deployment and management  
- Network infrastructure setup
- Resource allocation and cleanup
```

#### 2. Scoring Service (`services/scoringService.js`)
```javascript
// Real-time scoring and analysis
- Packet capture analysis
- Attack pattern detection
- WebSocket broadcasting
- Confidence scoring algorithms
```

#### 3. Database Models
```javascript
// Enhanced data models
- Match.js: Competition sessions
- Team.js: Team management
- ScoringEvent.js: Attack/defense events
- Enhanced associations and relationships
```

### API Endpoints

#### Match Management
```
GET  /api/matches          - List all matches
POST /api/matches          - Create new match (admin)
GET  /api/matches/:id      - Get match details
PUT  /api/matches/:id      - Update match configuration
POST /api/matches/:id/start - Start match
POST /api/matches/:id/end   - End match
GET  /api/matches/:id/scoreboard - Real-time scoreboard
GET  /api/matches/:id/events     - Match event timeline
POST /api/matches/:id/score      - Manual scoring (admin)
```

#### Team Management  
```
GET  /api/teams            - List all teams
POST /api/teams            - Create new team
GET  /api/teams/:id        - Get team details
PUT  /api/teams/:id        - Update team
POST /api/teams/:id/join   - Join team
POST /api/teams/:id/leave  - Leave team
GET  /api/teams/:id/stats  - Team performance statistics
```

#### WebSocket Events
```
ws://localhost:5000/ws/scoring
- subscribe_match: Get live match updates
- scoring_event: New scoring events
- match_started: Match state changes  
- match_ended: Final results
- live_events: Recent activity feed
```

## 🛠️ Installation & Setup

### 1. Install Dependencies
```bash
cd backend
npm install
# Installs ws package for WebSocket support
```

### 2. Database Setup
The new models will auto-sync in development:
```bash
npm run dev
# Models: Match, Team, ScoringEvent auto-created
```

### 3. Air-Gapped Deployment
For Proxmox environments, ensure Phase 1 offline infrastructure is deployed:
```bash
# Use the existing cyberrange-truly-offline-fixed.tar.gz
# New Phase 2 features will integrate automatically
```

### 4. Configuration
Environment variables in `.env`:
```bash
# Existing settings plus:
ENABLE_PACKET_ANALYSIS=true
PCAP_DIRECTORY=/opt/cyberrange/pcap-data
LOG_DIRECTORY=/var/log/cyberrange
ELK_ENDPOINT=http://172.16.200.136:9200  # Optional
```

## 🎮 Usage Guide

### Creating a Match
```javascript
POST /api/matches
{
  "name": "Red Team vs Blue Team",
  "matchType": "attack_defense", 
  "duration": 120,
  "maxTeams": 4,
  "teamsPerMatch": 2,
  "packetCaptureEnabled": true,
  "autoScoring": true,
  "networkConfig": {
    "isolation": true,
    "allowInterTeamCommunication": false
  },
  "vmConfig": {
    "templates": [
      {"templateId": 9001, "name": "Ubuntu-Target", "role": "target"},
      {"templateId": 9003, "name": "Kali-Attacker", "role": "attacker"}
    ]
  }
}
```

### Team Management
```javascript
// Create team
POST /api/teams
{
  "name": "Red Hawks",
  "description": "Elite penetration testing team",
  "color": "#FF0000",
  "maxMembers": 4
}

// Join team  
POST /api/teams/1/join
// Leave team
POST /api/teams/1/leave
```

### WebSocket Client Example
```javascript
const ws = new WebSocket('ws://localhost:5000/ws/scoring');

ws.onopen = () => {
  // Subscribe to match updates
  ws.send(JSON.stringify({
    type: 'subscribe_match',
    matchId: 1
  }));
};

ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  switch(data.type) {
    case 'scoring_event':
      updateScoreboard(data.event);
      break;
    case 'match_started':
      showMatchStarted(data);
      break;
  }
};
```

## 🔍 Scoring System

### Automated Attack Detection

#### Network Analysis
- **Port Scanning**: TCP connect patterns, multi-port probes
- **Brute Force**: Authentication attempts on SSH, RDP, SMB
- **Web Attacks**: HTTP request volume analysis  
- **DNS Enumeration**: Query pattern recognition
- **Lateral Movement**: Multi-target connection analysis

#### Point Values
```javascript
{
  "network_compromise": 25,
  "vulnerability_exploit": 30, 
  "attack_success": 50,
  "lateral_movement": 35,
  "flag_capture": 100
}
```

#### Confidence Levels
- **High (0.9+)**: Clear attack signatures, multiple indicators
- **Medium (0.7-0.9)**: Probable attacks, good evidence  
- **Low (0.5-0.7)**: Possible attacks, requires review

### Manual Scoring
Admins can add manual scores for:
- Social engineering attempts
- Physical security bypasses
- Custom challenge completions
- Penalty deductions

## 🌐 Air-Gapped Features

### Packet Analysis  
- Uses existing Phase 1 packet capture infrastructure
- Analyzes PCAP files from `/opt/cyberrange/pcap-data/`
- Falls back to file size analysis if tshark unavailable
- Processes recent captures every 30 seconds

### VM Management
- Integrates with Proxmox API for VM deployment
- Automatic subnet allocation per team
- Template-based VM creation (9001-9004 series)
- Network isolation with iptables rules

### Monitoring Integration
- Optional ELK stack connectivity
- Syslog analysis capabilities  
- Local log file monitoring
- Dashboard generation without internet

## 📊 Performance & Scalability

### Match Concurrency
- Multiple active matches supported
- Independent network segments per match
- Resource allocation based on team count
- Automatic cleanup after match completion

### Real-Time Performance
- WebSocket connections per client
- Efficient packet analysis batching
- Database query optimization
- Memory management for large events

### Storage Requirements
- PCAP files: ~100MB per team per hour
- Event data: ~1KB per scoring event
- Team data: ~10KB per team
- Match data: ~50KB per match

## 🔧 Troubleshooting

### Common Issues

#### WebSocket Connection Failures
```bash
# Check if WebSocket server is running
curl -i -N -H "Connection: Upgrade" \
  -H "Upgrade: websocket" \
  -H "Origin: http://localhost:5000" \
  http://localhost:5000/ws/scoring
```

#### Packet Analysis Not Working
```bash
# Verify tshark installation
which tshark
# Check PCAP directory permissions
ls -la /opt/cyberrange/pcap-data/
# Verify packet capture is running
ps aux | grep tcpdump
```

#### Game Engine Errors
```bash  
# Check Proxmox connectivity
qm list
# Verify VM templates exist  
qm list | grep 900[1-4]
# Check network bridge
ip link show vmbr0
```

### Debug Mode
```bash
export DEBUG=cyberrange:*
npm run dev
# Enables detailed logging for all components
```

## 🚗 Roadmap

### Phase 3 Plans
- **AI-Powered Analysis**: Machine learning attack detection  
- **Blockchain Scoring**: Immutable scoring ledger
- **Advanced Networking**: SDN integration, traffic shaping
- **Mobile Support**: Team mobile apps for monitoring
- **Tournament Mode**: Multi-round competitions with playoffs

### Integration Opportunities  
- **SIEM Integration**: Splunk, QRadar connectivity
- **Threat Intelligence**: IOC and TTP correlation
- **Forensic Tools**: Memory analysis, disk imaging
- **Cloud Deployment**: AWS, Azure, GCP variants

## 📞 Support

### Documentation
- API documentation available at `/api/health`
- WebSocket events documented in source code  
- Database schema in `models/` directory

### Logging
```bash
# View comprehensive logs
npm run logs
# Filter by component
npm run logs:security
npm run logs:errors
```

### Development
```bash
# Start with hot reload
npm run dev
# Debug specific component
DEBUG=cyberrange:scoring npm run dev
# Check health status
curl http://localhost:5000/api/health
```

## 🎯 Conclusion

Phase 2 transforms CyberRange into a comprehensive cyber-warfare platform ready for real-world competitions. With automated scoring, real-time updates, and air-gapped operation, it provides everything needed to run engaging cybersecurity competitions in secure environments.

The modular architecture ensures easy extension and customization while maintaining robust performance under competitive conditions. Whether for training exercises, academic competitions, or professional tournaments, Phase 2 delivers enterprise-grade competition management capabilities.

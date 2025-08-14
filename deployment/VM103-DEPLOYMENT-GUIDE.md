# CyberRange Phase 2 Deployment Guide for VM 103

## Target Environment
- **Host**: VM 103 (dhruv-main)
- **IP Address**: 172.16.200.136
- **Current Services**: CyberRange frontend and backend already running

## Quick Deployment

### Option 1: Local Deployment (if you're on VM 103)
```bash
# Navigate to deployment directory
cd /home/kali/Downloads/cyberrangev1-main/deployment

# Run the deployment script locally
sudo ./deploy-phase2-vm103.sh
```

### Option 2: Remote Deployment (from another machine)
```bash
# Copy deployment files to VM 103
scp -r /home/kali/Downloads/cyberrangev1-main user@172.16.200.136:/tmp/cyberrangev1-phase2

# SSH to VM 103 and run deployment
ssh user@172.16.200.136
cd /tmp/cyberrangev1-phase2/deployment
sudo ./deploy-phase2-vm103.sh
```

## What the Script Does

### 🔧 **Phase 2 Upgrade Process**
1. **Backup**: Creates backup of existing CyberRange installation
2. **Dependencies**: Installs WebSocket package (`ws@^8.18.0`)
3. **Backend Files**: Deploys new Phase 2 services and models
4. **Infrastructure**: Sets up packet capture and monitoring
5. **Network**: Configures firewall rules for team isolation
6. **Services**: Restarts backend with Phase 2 features
7. **Verification**: Tests all new endpoints and services

### 📁 **New Files Deployed**
```
backend/
├── models/
│   ├── Team.js              # Team management
│   ├── Match.js             # Competition matches  
│   ├── ScoringEvent.js      # Scoring events
│   └── index.js             # Updated associations
├── services/
│   ├── scoringService.js    # Real-time scoring
│   └── gameEngine.js        # Match management
├── routes/
│   ├── matches.js           # Match API endpoints
│   └── teams.js             # Team API endpoints
└── server.js                # Updated with Phase 2 features
```

### 🌐 **Infrastructure Setup**
```bash
/opt/cyberrange/             # Base directory
├── pcap-data/               # Packet captures
├── scripts/                 # Management scripts
└── deployment-summary.txt   # Deployment info

/var/log/cyberrange/         # Logs directory
├── backend.log              # Backend service logs
└── match-*/                 # Match-specific logs
```

## Post-Deployment Verification

### ✅ **Check Services**
```bash
# Backend health check
curl http://172.16.200.136:5000/api/health

# WebSocket test
curl -i -N -H "Connection: Upgrade" \
  -H "Upgrade: websocket" \
  http://172.16.200.136:5000/ws/scoring

# Packet capture service
sudo systemctl status cyberrange-pcap.service
```

### 🌐 **Access URLs**
- **Frontend**: http://172.16.200.136:3000
- **Backend API**: http://172.16.200.136:5000/api
- **Health Check**: http://172.16.200.136:5000/api/health
- **WebSocket**: ws://172.16.200.136:5000/ws/scoring

### 📊 **New API Endpoints**
```bash
# Team Management
GET  /api/teams              # List teams
POST /api/teams              # Create team
GET  /api/teams/:id          # Team details
POST /api/teams/:id/join     # Join team

# Match Management  
GET  /api/matches            # List matches
POST /api/matches            # Create match (admin)
GET  /api/matches/:id        # Match details
POST /api/matches/:id/start  # Start match
GET  /api/matches/:id/scoreboard # Live scoreboard
```

## Available VMs for Competitions

### 🔴 **Attacker VMs (Kali Linux)**
- VM 101: kali-26.128
- VM 104: kali-26.133  
- VM 105: kali-26.120
- VM 106: kali-26.121
- VM 107: kali-26.117
- VM 108: kali-26.137
- VM 109: kali-26.124
- VM 110: kali-26.114

### 🎯 **Target VMs**
- VM 102: Win-26.128 (Windows)

### 🏠 **Host VM (Not Used in Competitions)**
- VM 103: dhruv-main (172.16.200.136) - CyberRange host

## Creating Your First Competition

### 1. Create Teams
```bash
curl -X POST http://172.16.200.136:5000/api/teams \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{
    "name": "Red Team",
    "description": "Elite hackers",
    "color": "#FF0000"
  }'
```

### 2. Create Match
```bash
curl -X POST http://172.16.200.136:5000/api/matches \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN" \
  -d '{
    "name": "Red vs Blue Competition",
    "matchType": "attack_defense",
    "duration": 120,
    "maxTeams": 4,
    "packetCaptureEnabled": true,
    "autoScoring": true
  }'
```

### 3. Add Teams to Match
```bash
curl -X POST http://172.16.200.136:5000/api/matches/1/teams \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN" \
  -d '{"teamIds": [1, 2]}'
```

### 4. Start Match
```bash
curl -X POST http://172.16.200.136:5000/api/matches/1/start \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN"
```

### 5. Monitor Live Scoreboard
```javascript
// WebSocket client example
const ws = new WebSocket('ws://172.16.200.136:5000/ws/scoring');

ws.onopen = () => {
  ws.send(JSON.stringify({
    type: 'subscribe_match',
    matchId: 1
  }));
};

ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  console.log('Live update:', data);
};
```

## Network Architecture

### 🌐 **Network Segmentation**
- **Host Network**: 172.16.200.0/24 (VM 103)
- **Team Networks**: 172.16.201.x/28 (Isolated per team)
- **Competition VMs**: 172.16.26.x/24 (Existing VMs)

### 🔒 **Security Features**
- Team network isolation via iptables
- Packet capture for all competition traffic
- Real-time attack detection and scoring
- Firewall rules for match-specific networking

## Troubleshooting

### 🚨 **Common Issues**

#### Backend Won't Start
```bash
# Check logs
tail -f /var/log/cyberrange/backend.log

# Check if ports are available
sudo netstat -tulpn | grep :5000

# Restart manually
cd /home/user/cyberrangev1-main/backend
npm start
```

#### WebSocket Connection Failed
```bash
# Check if WebSocket server is running
curl -i -N -H "Connection: Upgrade" \
  -H "Upgrade: websocket" \
  http://172.16.200.136:5000/ws/scoring

# Check firewall
sudo iptables -L | grep 5000
```

#### Packet Capture Not Working
```bash
# Check service status
sudo systemctl status cyberrange-pcap.service

# Check tcpdump permissions
sudo tcpdump -i vmbr0 -c 1

# Check PCAP directory
ls -la /opt/cyberrange/pcap-data/
```

#### Database Issues
```bash
# Check database connection
mysql -u your_user -p -e "SHOW DATABASES;"

# Check if new tables were created
mysql -u your_user -p -e "USE cyberrange; SHOW TABLES;"
```

### 📋 **Debug Commands**
```bash
# Full system status
curl -s http://172.16.200.136:5000/api/health | python3 -m json.tool

# View recent logs
sudo journalctl -u cyberrange-pcap.service -f

# Check VM status
qm list

# Test network connectivity
ping 172.16.200.136
```

## Support & Documentation

- **Deployment Summary**: `/opt/cyberrange/deployment-summary.txt`
- **Backend Logs**: `/var/log/cyberrange/backend.log`  
- **Phase 2 Documentation**: `../PHASE2_README.md`
- **Original README**: `../README.md`

## 🎉 Success Indicators

After successful deployment, you should see:
- ✅ Backend health check returns Phase 2 features
- ✅ WebSocket server accepting connections
- ✅ Packet capture service running
- ✅ New API endpoints responding
- ✅ Frontend can create teams and matches
- ✅ Real-time scoring system operational

Your CyberRange is now ready for dynamic cyber-warfare competitions! 🚀

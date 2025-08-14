const { ScoringEvent, Team, Match, User } = require('../models');
const { Op } = require('sequelize');
const WebSocket = require('ws');
const { exec } = require('child_process');
const fs = require('fs').promises;
const path = require('path');

class ScoringService {
  constructor() {
    this.wss = null;
    this.activeMatches = new Map();
    this.scoringRules = new Map();
    this.packetAnalyzers = new Map();
    this.elkAvailable = false;
    
    // Air-gapped specific configurations
    this.pcapDir = '/opt/cyberrange/pcap-data';
    this.logDir = '/var/log/cyberrange';
    this.confidenceThresholds = {
      high: 0.9,
      medium: 0.7,
      low: 0.5
    };
  }

  // Initialize WebSocket server for real-time updates
  initializeWebSocket(server) {
    this.wss = new WebSocket.Server({ server, path: '/ws/scoring' });
    
    this.wss.on('connection', (ws, req) => {
      console.log('New WebSocket connection for scoring');
      
      // Send current active matches and scores
      this.sendActiveMatchesToClient(ws);
      
      ws.on('message', async (data) => {
        try {
          const message = JSON.parse(data);
          await this.handleWebSocketMessage(ws, message);
        } catch (error) {
          console.error('WebSocket message error:', error);
          ws.send(JSON.stringify({ type: 'error', message: 'Invalid message format' }));
        }
      });

      ws.on('close', () => {
        console.log('WebSocket connection closed');
      });
    });

    return this.wss;
  }

  // Handle incoming WebSocket messages
  async handleWebSocketMessage(ws, message) {
    switch (message.type) {
      case 'subscribe_match':
        // Subscribe to specific match updates
        ws.matchId = message.matchId;
        await this.sendMatchScoreboard(ws, message.matchId);
        break;
        
      case 'get_live_events':
        // Get recent scoring events for a match
        await this.sendLiveEvents(ws, message.matchId, message.limit || 10);
        break;
        
      case 'admin_manual_score':
        // Admin manual scoring
        if (message.isAdmin) {
          await this.processManualScore(message.data);
        }
        break;
    }
  }

  // Start match scoring for a specific match
  async startMatchScoring(matchId) {
    try {
      const match = await Match.findByPk(matchId, {
        include: [{ model: Team, as: 'teams' }]
      });

      if (!match) {
        throw new Error('Match not found');
      }

      // Store match configuration
      this.activeMatches.set(matchId, {
        match,
        teams: match.teams,
        startTime: new Date(),
        scoringRules: match.scoringRules,
        autoScoring: match.autoScoring,
        elkIntegration: match.elkIntegration,
        packetCapture: match.packetCaptureEnabled
      });

      console.log(`Started scoring for match ${matchId}: ${match.name}`);

      // Start packet analysis if enabled
      if (match.packetCaptureEnabled) {
        this.startPacketAnalysis(matchId);
      }

      // Start log monitoring if enabled
      if (match.logAnalysisEnabled) {
        this.startLogAnalysis(matchId);
      }

      // Check ELK availability
      if (match.elkIntegration) {
        await this.checkElkAvailability();
      }

      return true;
    } catch (error) {
      console.error('Error starting match scoring:', error);
      throw error;
    }
  }

  // Stop match scoring
  async stopMatchScoring(matchId) {
    try {
      const matchData = this.activeMatches.get(matchId);
      if (!matchData) {
        return false;
      }

      // Stop packet analysis
      if (this.packetAnalyzers.has(matchId)) {
        this.packetAnalyzers.get(matchId).kill();
        this.packetAnalyzers.delete(matchId);
      }

      // Remove from active matches
      this.activeMatches.delete(matchId);

      console.log(`Stopped scoring for match ${matchId}`);
      return true;
    } catch (error) {
      console.error('Error stopping match scoring:', error);
      throw error;
    }
  }

  // Analyze network packets for scoring events
  async startPacketAnalysis(matchId) {
    try {
      const matchData = this.activeMatches.get(matchId);
      if (!matchData) return;

      // Monitor packet capture files for new captures
      const pcapWatcher = setInterval(async () => {
        try {
          await this.analyzePcapFiles(matchId);
        } catch (error) {
          console.error('PCAP analysis error:', error);
        }
      }, 30000); // Check every 30 seconds

      this.packetAnalyzers.set(matchId, { kill: () => clearInterval(pcapWatcher) });
    } catch (error) {
      console.error('Error starting packet analysis:', error);
    }
  }

  // Analyze packet capture files for scoring events
  async analyzePcapFiles(matchId) {
    try {
      const files = await fs.readdir(this.pcapDir);
      const recentPcaps = files
        .filter(f => f.endsWith('.pcap'))
        .map(f => ({
          name: f,
          path: path.join(this.pcapDir, f),
          timestamp: this.extractTimestampFromFilename(f)
        }))
        .filter(f => f.timestamp && (Date.now() - f.timestamp) < 300000) // Last 5 minutes
        .sort((a, b) => b.timestamp - a.timestamp);

      for (const pcap of recentPcaps.slice(0, 3)) { // Process latest 3 files
        await this.analyzePacketCapture(matchId, pcap);
      }
    } catch (error) {
      console.error('Error analyzing PCAP files:', error);
    }
  }

  // Extract timestamp from PCAP filename
  extractTimestampFromFilename(filename) {
    // Format: cyberrange-YYYYMMDD-HHMMSS.pcap
    const match = filename.match(/cyberrange-(\d{8})-(\d{6})\.pcap/);
    if (!match) return null;

    const [, date, time] = match;
    const year = date.substr(0, 4);
    const month = date.substr(4, 2) - 1; // Month is 0-indexed
    const day = date.substr(6, 2);
    const hour = time.substr(0, 2);
    const minute = time.substr(2, 2);
    const second = time.substr(4, 2);

    return new Date(year, month, day, hour, minute, second).getTime();
  }

  // Analyze individual packet capture for scoring events
  async analyzePacketCapture(matchId, pcapInfo) {
    try {
      // Use tshark for packet analysis if available
      const tsharkCommand = `tshark -r "${pcapInfo.path}" -T json -e ip.src -e ip.dst -e tcp.port -e tcp.flags -e http.request.method -e dns.qry.name -c 1000`;

      return new Promise((resolve, reject) => {
        exec(tsharkCommand, { timeout: 30000 }, async (error, stdout, stderr) => {
          if (error) {
            // Fallback to simple packet counting if tshark not available
            await this.analyzePacketBasic(matchId, pcapInfo);
            resolve();
            return;
          }

          try {
            const packets = JSON.parse(`[${stdout.trim().replace(/}\n{/g, '},{')}]`);
            await this.processPacketData(matchId, packets, pcapInfo);
            resolve();
          } catch (parseError) {
            console.error('Error parsing tshark output:', parseError);
            resolve();
          }
        });
      });
    } catch (error) {
      console.error('Error analyzing packet capture:', error);
    }
  }

  // Basic packet analysis without tshark
  async analyzePacketBasic(matchId, pcapInfo) {
    try {
      const stats = await fs.stat(pcapInfo.path);
      const fileSize = stats.size;

      // Estimate activity based on file size
      if (fileSize > 1000000) { // > 1MB suggests significant activity
        await this.createScoringEvent(matchId, null, {
          eventType: 'network_compromise',
          points: 15,
          confidence: 0.6,
          description: `High network activity detected (${Math.round(fileSize/1024/1024)}MB)`,
          sourceType: 'auto_network',
          evidence: { pcapFile: pcapInfo.name, fileSize }
        });
      }
    } catch (error) {
      console.error('Basic packet analysis error:', error);
    }
  }

  // Process parsed packet data for scoring
  async processPacketData(matchId, packets, pcapInfo) {
    try {
      const matchData = this.activeMatches.get(matchId);
      if (!matchData) return;

      const attackPatterns = {
        portScanning: this.detectPortScanning(packets),
        bruteForce: this.detectBruteForce(packets),
        webAttacks: this.detectWebAttacks(packets),
        dnsEnumeration: this.detectDnsEnumeration(packets),
        lateralMovement: this.detectLateralMovement(packets)
      };

      // Create scoring events for detected attacks
      for (const [attackType, detections] of Object.entries(attackPatterns)) {
        for (const detection of detections) {
          const teamId = await this.identifyTeamFromIP(detection.srcIp, matchData.teams);
          if (teamId) {
            await this.createScoringEvent(matchId, teamId, {
              eventType: this.mapAttackTypeToEventType(attackType),
              eventSubtype: detection.subtype,
              points: detection.points,
              confidence: detection.confidence,
              description: detection.description,
              sourceType: 'auto_network',
              networkFlow: {
                srcIp: detection.srcIp,
                dstIp: detection.dstIp,
                srcPort: detection.srcPort,
                dstPort: detection.dstPort,
                protocol: detection.protocol
              },
              evidence: detection.evidence,
              packetCaptureFile: pcapInfo.name
            });
          }
        }
      }
    } catch (error) {
      console.error('Error processing packet data:', error);
    }
  }

  // Detect port scanning patterns
  detectPortScanning(packets) {
    const scanMap = new Map();
    const detections = [];

    packets.forEach(packet => {
      const srcIp = packet['ip.src'];
      const dstIp = packet['ip.dst'];
      const dstPort = packet['tcp.port'];

      if (srcIp && dstIp && dstPort) {
        const key = `${srcIp}-${dstIp}`;
        if (!scanMap.has(key)) {
          scanMap.set(key, { ports: new Set(), count: 0 });
        }
        scanMap.get(key).ports.add(dstPort);
        scanMap.get(key).count++;
      }
    });

    // Identify potential port scans
    scanMap.forEach((data, key) => {
      if (data.ports.size > 10) { // More than 10 unique ports
        const [srcIp, dstIp] = key.split('-');
        detections.push({
          srcIp,
          dstIp,
          subtype: 'port_scan',
          points: 25,
          confidence: data.ports.size > 50 ? 0.9 : 0.7,
          description: `Port scan detected: ${data.ports.size} ports scanned`,
          evidence: { portsScanned: Array.from(data.ports).slice(0, 20) }
        });
      }
    });

    return detections;
  }

  // Detect brute force patterns
  detectBruteForce(packets) {
    const authAttempts = new Map();
    const detections = [];

    packets.forEach(packet => {
      const srcIp = packet['ip.src'];
      const dstPort = packet['tcp.port'];

      // Common authentication ports
      if (['22', '23', '21', '3389', '445'].includes(dstPort)) {
        const key = `${srcIp}-${dstPort}`;
        authAttempts.set(key, (authAttempts.get(key) || 0) + 1);
      }
    });

    authAttempts.forEach((count, key) => {
      if (count > 20) { // More than 20 attempts
        const [srcIp, port] = key.split('-');
        const service = this.getServiceName(port);
        detections.push({
          srcIp,
          dstPort: port,
          subtype: 'brute_force',
          points: 30,
          confidence: count > 100 ? 0.9 : 0.8,
          description: `Brute force attack on ${service} (${count} attempts)`,
          evidence: { attempts: count, service }
        });
      }
    });

    return detections;
  }

  // Detect web attack patterns
  detectWebAttacks(packets) {
    const detections = [];
    const webPackets = packets.filter(p => p['tcp.port'] === '80' || p['tcp.port'] === '443');

    if (webPackets.length > 50) { // Significant web traffic
      detections.push({
        srcIp: webPackets[0]['ip.src'],
        dstIp: webPackets[0]['ip.dst'],
        dstPort: webPackets[0]['tcp.port'],
        subtype: 'web_exploitation',
        points: 20,
        confidence: 0.6,
        description: `Web exploitation attempt detected (${webPackets.length} requests)`,
        evidence: { requestCount: webPackets.length }
      });
    }

    return detections;
  }

  // Detect DNS enumeration
  detectDnsEnumeration(packets) {
    const dnsQueries = packets
      .filter(p => p['dns.qry.name'])
      .map(p => p['dns.qry.name'])
      .filter(Boolean);

    if (dnsQueries.length > 20) { // Many DNS queries
      return [{
        srcIp: packets.find(p => p['dns.qry.name'])?.['ip.src'],
        subtype: 'dns_enumeration',
        points: 15,
        confidence: 0.7,
        description: `DNS enumeration detected (${dnsQueries.length} queries)`,
        evidence: { queries: dnsQueries.slice(0, 10) }
      }];
    }

    return [];
  }

  // Detect lateral movement
  detectLateralMovement(packets) {
    const connections = new Map();
    packets.forEach(packet => {
      const srcIp = packet['ip.src'];
      if (srcIp) {
        connections.set(srcIp, (connections.get(srcIp) || new Set()).add(packet['ip.dst']));
      }
    });

    const detections = [];
    connections.forEach((targets, srcIp) => {
      if (targets.size > 5) { // Connecting to multiple targets
        detections.push({
          srcIp,
          subtype: 'lateral_movement',
          points: 35,
          confidence: 0.8,
          description: `Lateral movement detected to ${targets.size} targets`,
          evidence: { targetCount: targets.size, targets: Array.from(targets).slice(0, 5) }
        });
      }
    });

    return detections;
  }

  // Map attack type to scoring event type
  mapAttackTypeToEventType(attackType) {
    const mapping = {
      portScanning: 'network_compromise',
      bruteForce: 'vulnerability_exploit',
      webAttacks: 'attack_success',
      dnsEnumeration: 'network_compromise',
      lateralMovement: 'lateral_movement'
    };
    return mapping[attackType] || 'attack_success';
  }

  // Get service name from port
  getServiceName(port) {
    const services = {
      '22': 'SSH', '23': 'Telnet', '21': 'FTP',
      '3389': 'RDP', '445': 'SMB', '80': 'HTTP',
      '443': 'HTTPS', '53': 'DNS'
    };
    return services[port] || `Port ${port}`;
  }

  // Identify team from IP address
  async identifyTeamFromIP(ipAddress, teams) {
    // Check if IP belongs to any team's assigned VMs
    for (const team of teams) {
      if (team.assignedVMs && team.assignedVMs.length > 0) {
        // This would need integration with VM IP discovery
        // For now, use a simple IP range mapping
        const teamSubnet = this.getTeamSubnet(team.id);
        if (this.isIpInSubnet(ipAddress, teamSubnet)) {
          return team.id;
        }
      }
    }
    return null;
  }

  // Get team subnet based on team ID
  getTeamSubnet(teamId) {
    // Simple subnet allocation: 172.16.200.{teamId*10}/28
    const baseIP = 200 + (teamId * 10);
    return `172.16.${baseIP}.0/28`;
  }

  // Check if IP is in subnet
  isIpInSubnet(ip, subnet) {
    // Simple implementation - in production, use proper IP subnet library
    const [subnetBase] = subnet.split('/');
    const ipParts = ip.split('.');
    const subnetParts = subnetBase.split('.');
    
    // Check first 3 octets
    for (let i = 0; i < 3; i++) {
      if (ipParts[i] !== subnetParts[i]) return false;
    }
    
    return true;
  }

  // Create a new scoring event
  async createScoringEvent(matchId, teamId, eventData) {
    try {
      const scoringEvent = await ScoringEvent.create({
        matchId,
        teamId,
        ...eventData
      });

      // Update team score if teamId provided
      if (teamId && eventData.finalPoints) {
        await this.updateTeamScore(teamId, eventData.finalPoints);
      }

      // Broadcast update via WebSocket
      await this.broadcastScoringEvent(matchId, scoringEvent);

      return scoringEvent;
    } catch (error) {
      console.error('Error creating scoring event:', error);
      throw error;
    }
  }

  // Update team total score
  async updateTeamScore(teamId, pointsDelta) {
    try {
      const team = await Team.findByPk(teamId);
      if (team) {
        team.currentPoints = Math.max(0, team.currentPoints + pointsDelta);
        team.lastActivity = new Date();
        await team.save();
      }
    } catch (error) {
      console.error('Error updating team score:', error);
    }
  }

  // Broadcast scoring event to WebSocket clients
  async broadcastScoringEvent(matchId, scoringEvent) {
    if (!this.wss) return;

    const message = {
      type: 'scoring_event',
      matchId,
      event: {
        id: scoringEvent.id,
        teamId: scoringEvent.teamId,
        eventType: scoringEvent.eventType,
        points: scoringEvent.finalPoints,
        description: scoringEvent.description,
        timestamp: scoringEvent.createdAt
      }
    };

    this.wss.clients.forEach(client => {
      if (client.matchId === matchId && client.readyState === WebSocket.OPEN) {
        client.send(JSON.stringify(message));
      }
    });
  }

  // Send active matches to WebSocket client
  async sendActiveMatchesToClient(ws) {
    try {
      const activeMatchIds = Array.from(this.activeMatches.keys());
      const matches = [];

      for (const matchId of activeMatchIds) {
        const matchData = this.activeMatches.get(matchId);
        matches.push({
          id: matchId,
          name: matchData.match.name,
          status: matchData.match.status,
          teams: matchData.teams.map(team => ({
            id: team.id,
            name: team.name,
            points: team.currentPoints,
            color: team.color
          }))
        });
      }

      ws.send(JSON.stringify({
        type: 'active_matches',
        matches
      }));
    } catch (error) {
      console.error('Error sending active matches:', error);
    }
  }

  // Send match scoreboard
  async sendMatchScoreboard(ws, matchId) {
    try {
      const match = await Match.findByPk(matchId, {
        include: [{
          model: Team,
          as: 'teams',
          include: [{
            model: ScoringEvent,
            as: 'scoringEvents',
            where: { matchId, isActive: true },
            required: false
          }]
        }]
      });

      if (!match) return;

      const scoreboard = match.teams
        .map(team => ({
          id: team.id,
          name: team.name,
          color: team.color,
          points: team.currentPoints,
          flags: team.totalFlags,
          lastActivity: team.lastActivity,
          recentEvents: team.scoringEvents
            .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
            .slice(0, 5)
            .map(event => ({
              type: event.eventType,
              points: event.finalPoints,
              time: event.createdAt
            }))
        }))
        .sort((a, b) => b.points - a.points);

      ws.send(JSON.stringify({
        type: 'scoreboard',
        matchId,
        scoreboard,
        lastUpdate: new Date()
      }));
    } catch (error) {
      console.error('Error sending scoreboard:', error);
    }
  }

  // Send live events
  async sendLiveEvents(ws, matchId, limit = 10) {
    try {
      const events = await ScoringEvent.findAll({
        where: { matchId, isActive: true },
        include: [
          { model: Team, as: 'team', attributes: ['name', 'color'] },
          { model: User, as: 'user', attributes: ['username'], required: false }
        ],
        order: [['createdAt', 'DESC']],
        limit
      });

      ws.send(JSON.stringify({
        type: 'live_events',
        matchId,
        events: events.map(event => ({
          id: event.id,
          type: event.eventType,
          subtype: event.eventSubtype,
          points: event.finalPoints,
          team: event.team,
          user: event.user?.username,
          description: event.description,
          timestamp: event.createdAt,
          confidence: event.confidence
        }))
      }));
    } catch (error) {
      console.error('Error sending live events:', error);
    }
  }

  // Check ELK availability
  async checkElkAvailability() {
    try {
      // Try to connect to Elasticsearch
      const { exec } = require('child_process');
      return new Promise((resolve) => {
        exec('curl -s http://172.16.200.136:9200/_cluster/health', (error, stdout) => {
          if (error) {
            this.elkAvailable = false;
            console.log('ELK stack not available - continuing with packet-based analysis');
          } else {
            this.elkAvailable = true;
            console.log('ELK stack available - enabling enhanced log analysis');
          }
          resolve(this.elkAvailable);
        });
      });
    } catch (error) {
      this.elkAvailable = false;
      return false;
    }
  }

  // Get match statistics
  async getMatchStatistics(matchId) {
    try {
      const events = await ScoringEvent.findAll({
        where: { matchId },
        attributes: ['eventType', 'sourceType', 'finalPoints', 'confidence'],
        raw: true
      });

      const stats = {
        totalEvents: events.length,
        totalPoints: events.reduce((sum, e) => sum + e.finalPoints, 0),
        eventTypes: {},
        sourceTypes: {},
        averageConfidence: events.reduce((sum, e) => sum + e.confidence, 0) / events.length || 0
      };

      events.forEach(event => {
        stats.eventTypes[event.eventType] = (stats.eventTypes[event.eventType] || 0) + 1;
        stats.sourceTypes[event.sourceType] = (stats.sourceTypes[event.sourceType] || 0) + 1;
      });

      return stats;
    } catch (error) {
      console.error('Error getting match statistics:', error);
      return null;
    }
  }
}

module.exports = new ScoringService();

const { Match, Team, User, ScoringEvent } = require('../models');
const { Op } = require('sequelize');
const scoringService = require('./scoringService');
const proxmoxService = require('./proxmoxService');
const { exec } = require('child_process');
const fs = require('fs').promises;
const path = require('path');

class GameEngine {
  constructor() {
    this.activeMatches = new Map();
    this.matchTimers = new Map();
    this.vmService = null; // Will be initialized with VM management service
    this.flagService = null; // Will be initialized with flag service
    
    // Air-gapped environment configuration
    this.proxmoxConfig = {
      host: '172.16.200.136',
      baseDir: '/opt/cyberrange',
      vmTemplates: new Map(),
      networkSegments: new Map()
    };
  }

  // Initialize the game engine
  async initialize() {
    try {
      console.log('Initializing Game Engine...');
      
      // Check Proxmox API connectivity
      const healthCheck = await proxmoxService.healthCheck();
      if (healthCheck.status === 'healthy') {
        console.log('✅ Proxmox API connection successful');
      } else {
        console.warn('⚠️  Proxmox API unavailable:', healthCheck.message);
        console.log('Continuing without VM management capabilities...');
      }
      
      // Load VM templates and network configurations
      await this.loadVMTemplates();
      await this.loadNetworkSegments();
      
      // Resume any active matches
      await this.resumeActiveMatches();
      
      console.log('Game Engine initialized successfully');
      return true;
    } catch (error) {
      console.error('Error initializing Game Engine:', error);
      throw error;
    }
  }

  // Create a new match
  async createMatch(matchData, creatorId) {
    try {
      const match = await Match.create({
        ...matchData,
        createdBy: creatorId,
        status: 'created',
        networkConfig: matchData.networkConfig || this.getDefaultNetworkConfig(),
        vmConfig: matchData.vmConfig || this.getDefaultVMConfig(),
        scoringRules: matchData.scoringRules || this.getDefaultScoringRules()
      });

      console.log(`Created match: ${match.name} (ID: ${match.id})`);
      return match;
    } catch (error) {
      console.error('Error creating match:', error);
      throw error;
    }
  }

  // Start a match
  async startMatch(matchId, adminId) {
    try {
      const match = await Match.findByPk(matchId, {
        include: [{ model: Team, as: 'teams' }]
      });

      if (!match) {
        throw new Error('Match not found');
      }

      if (match.status !== 'ready') {
        throw new Error('Match is not ready to start');
      }

      // Validate teams have required members
      if (match.teams.length < 2) {
        throw new Error('Match requires at least 2 teams');
      }

      // Set up network infrastructure
      await this.setupMatchNetworkInfrastructure(match);

      // Deploy VMs for teams
      await this.deployMatchVMs(match);

      // Configure network monitoring
      await this.setupNetworkMonitoring(match);

      // Update match status
      match.status = 'active';
      match.startTime = new Date();
      await match.save();

      // Start scoring service
      await scoringService.startMatchScoring(matchId);

      // Set up match timer if duration is specified
      if (match.duration) {
        this.setupMatchTimer(matchId, match.duration);
      }

      // Store active match data
      this.activeMatches.set(matchId, {
        match,
        teams: match.teams,
        startTime: new Date(),
        infrastructure: {
          networks: [],
          vms: [],
          monitoring: {}
        }
      });

      console.log(`Started match: ${match.name} (ID: ${matchId})`);
      
      // Broadcast match start event
      if (scoringService.wss) {
        this.broadcastMatchEvent(matchId, 'match_started', {
          matchId,
          name: match.name,
          teams: match.teams.map(t => ({ id: t.id, name: t.name }))
        });
      }

      return true;
    } catch (error) {
      console.error('Error starting match:', error);
      throw error;
    }
  }

  // End a match
  async endMatch(matchId, adminId, reason = 'completed') {
    try {
      const match = await Match.findByPk(matchId);
      if (!match) {
        throw new Error('Match not found');
      }

      // Stop scoring service
      await scoringService.stopMatchScoring(matchId);

      // Clear match timer
      if (this.matchTimers.has(matchId)) {
        clearTimeout(this.matchTimers.get(matchId));
        this.matchTimers.delete(matchId);
      }

      // Stop and release VMs through Proxmox API
      console.log('Stopping match VMs...');
      const stopResult = await proxmoxService.stopMatchVMs(matchId);
      if (stopResult.success) {
        console.log(`✅ ${stopResult.message}`);
      }

      console.log('Releasing match VMs...');
      const releaseResult = await proxmoxService.releaseMatchVMs(matchId);
      if (releaseResult.success) {
        console.log(`✅ ${releaseResult.message}`);
      }

      // Generate final scores and statistics
      const finalResults = await this.generateFinalResults(matchId);

      // Update match status
      match.status = 'completed';
      match.endTime = new Date();
      match.endReason = reason;
      await match.save();

      // Remove from active matches
      this.activeMatches.delete(matchId);

      console.log(`Ended match: ${match.name} (ID: ${matchId}) - Reason: ${reason}`);

      // Broadcast match end event
      if (scoringService.wss) {
        this.broadcastMatchEvent(matchId, 'match_ended', {
          matchId,
          reason,
          finalResults
        });
      }

      return finalResults;
    } catch (error) {
      console.error('Error ending match:', error);
      throw error;
    }
  }

  // Set up network infrastructure for a match
  async setupMatchNetworkInfrastructure(match) {
    try {
      console.log(`Setting up network infrastructure for match ${match.id}`);
      
      const networkConfig = match.networkConfig;
      const matchData = this.activeMatches.get(match.id) || { infrastructure: { networks: [] } };

      // Create isolated network segments for each team
      for (const team of match.teams) {
        const teamSubnet = this.calculateTeamSubnet(team.id, match.id);
        const networkName = `cyberrange-match${match.id}-team${team.id}`;

        // Create team network using existing vmbr0 bridge
        const networkSetup = await this.createTeamNetwork(networkName, teamSubnet, team.id);
        
        matchData.infrastructure.networks.push({
          teamId: team.id,
          networkName,
          subnet: teamSubnet,
          bridgeInterface: networkSetup.bridge,
          isolationEnabled: networkConfig.isolation
        });

        console.log(`Created network for Team ${team.name}: ${teamSubnet}`);
      }

      // Configure inter-team network rules
      if (networkConfig.allowInterTeamCommunication) {
        await this.configureInterTeamNetworking(match.id, match.teams);
      }

      this.activeMatches.set(match.id, matchData);
    } catch (error) {
      console.error('Error setting up network infrastructure:', error);
      throw error;
    }
  }

  // Deploy VMs for match teams using Proxmox API
  async deployMatchVMs(match) {
    try {
      console.log(`Assigning VMs for match ${match.id}`);
      
      const matchData = this.activeMatches.get(match.id);
      const vmConfig = match.vmConfig;

      for (const team of match.teams) {
        // Define VM requirements based on match configuration
        const vmRequirements = vmConfig.templates.map(template => ({
          type: template.role === 'target' ? 'windows' : 'kali',
          role: template.role,
          name: template.name
        }));

        // Assign VMs through Proxmox service
        const assignmentResult = await proxmoxService.assignVMsToTeam(
          match.id, 
          team.id, 
          vmRequirements
        );

        if (assignmentResult.success) {
          // Update team assigned VMs
          const team_instance = await Team.findByPk(team.id);
          team_instance.assignedVMs = assignmentResult.assignedVMs.map(vm => ({
            vmId: vm.vmId,
            name: vm.name,
            type: vm.type,
            role: vm.role
          }));
          await team_instance.save();

          matchData.infrastructure.vms.push({
            teamId: team.id,
            vms: assignmentResult.assignedVMs
          });

          console.log(`✅ Assigned ${assignmentResult.assignedVMs.length} VMs to Team ${team.name}`);
        } else {
          console.error(`❌ Failed to assign VMs to Team ${team.name}:`, assignmentResult.error);
        }
      }

      // Start all assigned VMs
      console.log('Starting assigned VMs...');
      const startResult = await proxmoxService.startMatchVMs(match.id);
      if (startResult.success) {
        console.log(`✅ ${startResult.message}`);
      } else {
        console.warn(`⚠️  VM start issues: ${startResult.error}`);
      }

      this.activeMatches.set(match.id, matchData);
    } catch (error) {
      console.error('Error assigning match VMs:', error);
      throw error;
    }
  }

  // Set up network monitoring for the match
  async setupNetworkMonitoring(match) {
    try {
      console.log(`Setting up network monitoring for match ${match.id}`);

      const monitoringConfig = {
        packetCapture: match.packetCaptureEnabled,
        logAnalysis: match.logAnalysisEnabled,
        elkIntegration: match.elkIntegration
      };

      if (monitoringConfig.packetCapture) {
        // Start packet capture for match networks
        await this.startPacketCapture(match.id, match.teams);
      }

      if (monitoringConfig.logAnalysis) {
        // Configure log collection from VMs
        await this.setupLogCollection(match.id, match.teams);
      }

      const matchData = this.activeMatches.get(match.id);
      matchData.infrastructure.monitoring = monitoringConfig;
      this.activeMatches.set(match.id, matchData);

    } catch (error) {
      console.error('Error setting up network monitoring:', error);
      throw error;
    }
  }

  // Create team network segment
  async createTeamNetwork(networkName, subnet, teamId) {
    try {
      // For air-gapped Proxmox, we use existing vmbr0 and configure firewall rules
      const bridgeInterface = 'vmbr0';
      
      // Create firewall rules for team isolation
      const firewallRules = [
        // Allow team internal communication
        `iptables -A FORWARD -s ${subnet} -d ${subnet} -j ACCEPT`,
        // Block inter-team communication (can be modified based on match rules)
        `iptables -A FORWARD -s ${subnet} -d 172.16.200.0/24 -m comment --comment "team${teamId}-isolation" -j DROP`,
        // Allow team to internet (if needed)
        `iptables -A FORWARD -s ${subnet} -d 0.0.0.0/0 -j ACCEPT`,
        // Allow return traffic
        `iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT`
      ];

      // Apply firewall rules
      for (const rule of firewallRules) {
        try {
          await this.executeCommand(rule);
        } catch (ruleError) {
          console.warn(`Warning: Failed to apply firewall rule: ${rule}`);
        }
      }

      return {
        bridge: bridgeInterface,
        subnet,
        firewallRules
      };
    } catch (error) {
      console.error('Error creating team network:', error);
      throw error;
    }
  }

  // Deploy a VM for a team (using existing VMs in VM 103 environment)
  async deployVM(vmTemplate, team, match) {
    try {
      console.log(`Configuring VM ${vmTemplate.templateId} for Team ${team.name}: ${vmTemplate.name}`);
      
      // For VM 103 environment, we reuse existing VMs rather than cloning
      const vmId = vmTemplate.templateId;
      
      // Check if VM is already running
      const vmStatus = await this.getVMStatus(vmId);
      
      if (vmStatus !== 'running') {
        // Start VM if not running
        await this.executeCommand(`qm start ${vmId}`);
        console.log(`Started VM ${vmId}`);
        
        // Wait for VM to be ready
        await this.waitForVMReady(vmId);
      }
      
      // Configure network isolation for competition
      await this.configureVMNetworkForTeam(vmId, team, match);
      
      // Get assigned IP for this team
      const teamSubnet = this.calculateTeamSubnet(team.id, match.id);
      const vmIP = this.calculateVMIP(teamSubnet, vmTemplate.role);
      
      console.log(`Configured VM ${vmId} for Team ${team.name}: ${vmTemplate.name} (IP: ${vmIP})`);
      return vmId;
    } catch (error) {
      console.error('Error configuring VM:', error);
      // Return the VM ID even if configuration partially failed
      return vmTemplate.templateId;
    }
  }

  // Calculate team subnet for VM 103 environment
  calculateTeamSubnet(teamId, matchId) {
    // Use 172.16.201.x/28 networks for team isolation
    // Each team gets a /28 subnet (16 addresses)
    const teamOffset = (teamId - 1) * 16;
    const matchOffset = (matchId % 10) * 64; // Up to 10 matches per 201.x network
    const subnetBase = 201 + Math.floor(matchOffset / 256);
    const hostPart = (matchOffset % 256) + teamOffset;
    
    return `172.16.${subnetBase}.${hostPart}/28`;
  }

  // Calculate VM IP within team subnet
  calculateVMIP(teamSubnet, vmRole) {
    const [base] = teamSubnet.split('/');
    const parts = base.split('.');
    const baseIP = parseInt(parts[3]);
    
    // Assign IPs based on VM role
    const roleOffsets = {
      'target': 2,
      'attacker': 3,
      'defender': 4,
      'server': 5
    };
    
    const offset = roleOffsets[vmRole] || 2;
    parts[3] = (baseIP + offset).toString();
    return parts.join('.');
  }

  // Start packet capture for match
  async startPacketCapture(matchId, teams) {
    try {
      const pcapDir = `/opt/cyberrange/pcap-data/match-${matchId}`;
      await this.executeCommand(`mkdir -p ${pcapDir}`);

      // Start tcpdump for each team's traffic
      for (const team of teams) {
        const teamSubnet = this.calculateTeamSubnet(team.id, matchId);
        const pcapFile = `${pcapDir}/team-${team.id}-${Date.now()}.pcap`;
        
        const tcpdumpCommand = `tcpdump -i vmbr0 -w ${pcapFile} "net ${teamSubnet}" &`;
        await this.executeCommand(tcpdumpCommand);
        
        console.log(`Started packet capture for Team ${team.name}: ${pcapFile}`);
      }
    } catch (error) {
      console.error('Error starting packet capture:', error);
    }
  }

  // Set up match timer
  setupMatchTimer(matchId, durationMinutes) {
    const durationMs = durationMinutes * 60 * 1000;
    
    const timer = setTimeout(async () => {
      try {
        await this.endMatch(matchId, null, 'time_expired');
      } catch (error) {
        console.error('Error in match timer:', error);
      }
    }, durationMs);

    this.matchTimers.set(matchId, timer);
    console.log(`Set match timer for ${durationMinutes} minutes`);
  }

  // Generate final match results
  async generateFinalResults(matchId) {
    try {
      const match = await Match.findByPk(matchId, {
        include: [
          {
            model: Team,
            as: 'teams',
            include: [
              { model: ScoringEvent, as: 'scoringEvents', where: { matchId } }
            ]
          }
        ]
      });

      const results = {
        matchId,
        matchName: match.name,
        duration: match.endTime - match.startTime,
        teams: [],
        totalEvents: 0,
        statistics: {}
      };

      // Calculate team results
      for (const team of match.teams) {
        const teamResult = {
          teamId: team.id,
          teamName: team.name,
          finalScore: team.currentPoints,
          totalFlags: team.totalFlags,
          totalEvents: team.scoringEvents.length,
          eventBreakdown: {},
          achievements: []
        };

        // Event breakdown by type
        team.scoringEvents.forEach(event => {
          if (!teamResult.eventBreakdown[event.eventType]) {
            teamResult.eventBreakdown[event.eventType] = { count: 0, points: 0 };
          }
          teamResult.eventBreakdown[event.eventType].count++;
          teamResult.eventBreakdown[event.eventType].points += event.finalPoints;
        });

        // Determine achievements
        teamResult.achievements = this.calculateTeamAchievements(team, team.scoringEvents);

        results.teams.push(teamResult);
        results.totalEvents += team.scoringEvents.length;
      }

      // Sort teams by score
      results.teams.sort((a, b) => b.finalScore - a.finalScore);

      // Calculate overall statistics
      results.statistics = await scoringService.getMatchStatistics(matchId);

      return results;
    } catch (error) {
      console.error('Error generating final results:', error);
      throw error;
    }
  }

  // Calculate team achievements
  calculateTeamAchievements(team, events) {
    const achievements = [];
    
    if (events.length > 50) {
      achievements.push({ name: 'High Activity', description: 'Generated over 50 scoring events' });
    }
    
    if (team.currentPoints > 1000) {
      achievements.push({ name: 'Point Master', description: 'Scored over 1000 points' });
    }

    const attackTypes = new Set(events.map(e => e.eventType));
    if (attackTypes.size > 5) {
      achievements.push({ name: 'Versatile Attacker', description: 'Used multiple attack techniques' });
    }

    return achievements;
  }

  // Broadcast match event to WebSocket clients
  broadcastMatchEvent(matchId, eventType, data) {
    if (!scoringService.wss) return;

    const message = {
      type: eventType,
      matchId,
      timestamp: new Date(),
      ...data
    };

    scoringService.wss.clients.forEach(client => {
      if (client.readyState === 1) { // WebSocket.OPEN
        client.send(JSON.stringify(message));
      }
    });
  }

  // Execute shell command
  async executeCommand(command) {
    return new Promise((resolve, reject) => {
      exec(command, (error, stdout, stderr) => {
        if (error) {
          console.error(`Command failed: ${command}`, error);
          reject(error);
        } else {
          resolve({ stdout, stderr });
        }
      });
    });
  }

  // Get next available VM ID
  async getNextAvailableVMId() {
    try {
      const result = await this.executeCommand('qm list');
      const lines = result.stdout.split('\n');
      const vmIds = lines
        .slice(1)
        .map(line => parseInt(line.trim().split(/\s+/)[0]))
        .filter(id => !isNaN(id))
        .sort((a, b) => a - b);

      // Find first gap or use next number after highest
      let nextId = 1000;
      for (const id of vmIds) {
        if (id === nextId) {
          nextId++;
        } else if (id > nextId) {
          break;
        }
      }

      return nextId;
    } catch (error) {
      console.error('Error getting next VM ID:', error);
      return 1000 + Math.floor(Math.random() * 1000);
    }
  }

  // Wait for VM to be ready
  async waitForVMReady(vmId, expectedIP, maxWaitMs = 120000) {
    const startTime = Date.now();
    
    while (Date.now() - startTime < maxWaitMs) {
      try {
        const result = await this.executeCommand(`qm status ${vmId}`);
        if (result.stdout.includes('running')) {
          // VM is running, wait a bit more for network
          await new Promise(resolve => setTimeout(resolve, 30000));
          return true;
        }
      } catch (error) {
        // Continue waiting
      }
      
      await new Promise(resolve => setTimeout(resolve, 5000));
    }
    
    throw new Error(`VM ${vmId} failed to start within timeout`);
  }

  // Get VM IP address
  async getVMIPAddress(vmId) {
    try {
      // This would need to be implemented based on how IPs are assigned
      // For now, return a calculated IP
      return `172.16.200.${100 + vmId % 50}`;
    } catch (error) {
      console.error('Error getting VM IP:', error);
      return null;
    }
  }

  // Get VM status
  async getVMStatus(vmId) {
    try {
      const result = await this.executeCommand(`qm status ${vmId}`);
      if (result.stdout.includes('running')) {
        return 'running';
      } else if (result.stdout.includes('stopped')) {
        return 'stopped';
      } else {
        return 'unknown';
      }
    } catch (error) {
      console.error(`Error getting VM ${vmId} status:`, error.message);
      return 'unknown';
    }
  }

  // Configure VM network for team isolation
  async configureVMNetworkForTeam(vmId, team, match) {
    try {
      console.log(`Configuring network isolation for VM ${vmId}, Team ${team.name}`);
      
      const teamSubnet = this.calculateTeamSubnet(team.id, match.id);
      
      // Add iptables rules for this specific VM
      const vmIP = await this.getVMIPAddress(vmId);
      
      // Allow VM to communicate within team subnet
      await this.executeCommand(
        `iptables -I CYBERRANGE_TEAMS -s ${vmIP} -d ${teamSubnet} -j ACCEPT`
      ).catch(err => console.warn('Failed to add team subnet rule:', err.message));
      
      // Block VM from other team networks (will be added as other teams are configured)
      await this.executeCommand(
        `iptables -I CYBERRANGE_TEAMS -s ${vmIP} -d 172.16.201.0/16 ! -d ${teamSubnet} -j DROP`
      ).catch(err => console.warn('Failed to add isolation rule:', err.message));
      
      console.log(`Network configured for VM ${vmId}: ${vmIP} -> ${teamSubnet}`);
      return true;
    } catch (error) {
      console.warn(`Network configuration failed for VM ${vmId}:`, error.message);
      return false;
    }
  }

  // Configure inter-team networking (for attack/defense scenarios)
  async configureInterTeamNetworking(matchId, teams) {
    try {
      console.log(`Configuring inter-team networking for match ${matchId}`);
      
      // Remove isolation between teams to allow attacks
      for (let i = 0; i < teams.length; i++) {
        for (let j = 0; j < teams.length; j++) {
          if (i !== j) {
            const sourceSubnet = this.calculateTeamSubnet(teams[i].id, matchId);
            const targetSubnet = this.calculateTeamSubnet(teams[j].id, matchId);
            
            // Allow team i to attack team j
            await this.executeCommand(
              `iptables -I CYBERRANGE_TEAMS -s ${sourceSubnet} -d ${targetSubnet} -j ACCEPT`
            ).catch(err => console.warn('Failed to configure inter-team rule:', err.message));
          }
        }
      }
      
      console.log('Inter-team networking configured');
    } catch (error) {
      console.error('Error configuring inter-team networking:', error);
    }
  }

  // Set up log collection from VMs
  async setupLogCollection(matchId, teams) {
    try {
      console.log(`Setting up log collection for match ${matchId}`);
      
      const logDir = `/var/log/cyberrange/match-${matchId}`;
      await this.executeCommand(`mkdir -p ${logDir}`);
      
      // For each team, set up log forwarding (if possible)
      for (const team of teams) {
        const teamLogDir = `${logDir}/team-${team.id}`;
        await this.executeCommand(`mkdir -p ${teamLogDir}`);
        
        console.log(`Log collection configured for Team ${team.name}: ${teamLogDir}`);
      }
      
    } catch (error) {
      console.error('Error setting up log collection:', error);
    }
  }

  // Load VM templates based on actual Proxmox environment
  async loadVMTemplates() {
    // VM 103 (dhruv-main) specific configuration with actual available VMs
    const availableTemplates = [
      // Kali Linux VMs for attackers
      { templateId: 101, name: 'kali-26.128', role: 'attacker', os: 'linux', currentIp: '172.16.26.128' },
      { templateId: 104, name: 'kali-26.133', role: 'attacker', os: 'linux', currentIp: '172.16.26.133' },
      { templateId: 105, name: 'kali-26.120', role: 'attacker', os: 'linux', currentIp: '172.16.26.120' },
      { templateId: 106, name: 'kali-26.121', role: 'attacker', os: 'linux', currentIp: '172.16.26.121' },
      { templateId: 107, name: 'kali-26.117', role: 'attacker', os: 'linux', currentIp: '172.16.26.117' },
      { templateId: 108, name: 'kali-26.137', role: 'attacker', os: 'linux', currentIp: '172.16.26.137' },
      { templateId: 109, name: 'kali-26.124', role: 'attacker', os: 'linux', currentIp: '172.16.26.124' },
      { templateId: 110, name: 'kali-26.114', role: 'attacker', os: 'linux', currentIp: '172.16.26.114' },
      
      // Windows VM for targets
      { templateId: 102, name: 'Win-26.128', role: 'target', os: 'windows', currentIp: '172.16.26.128' },
      
      // CyberRange host (not used in competitions)
      { templateId: 103, name: 'dhruv-main', role: 'host', os: 'linux', currentIp: '172.16.200.136' }
    ];

    // Filter out the host VM and store available VMs for competitions
    const competitionVMs = availableTemplates.filter(vm => vm.role !== 'host');
    
    competitionVMs.forEach(template => {
      this.proxmoxConfig.vmTemplates.set(template.name, template);
    });

    console.log('Loaded VM templates for competitions:', Array.from(this.proxmoxConfig.vmTemplates.keys()));
    console.log(`Available Kali VMs: ${competitionVMs.filter(vm => vm.role === 'attacker').length}`);
    console.log(`Available Target VMs: ${competitionVMs.filter(vm => vm.role === 'target').length}`);
  }

  // Load network segments
  async loadNetworkSegments() {
    // Define network segments for air-gapped environment
    const segments = [
      { name: 'management', subnet: '172.16.200.0/26', vlan: 200 },
      { name: 'teams', subnet: '172.16.201.0/24', vlan: 201 },
      { name: 'targets', subnet: '172.16.202.0/24', vlan: 202 }
    ];

    segments.forEach(segment => {
      this.proxmoxConfig.networkSegments.set(segment.name, segment);
    });

    console.log('Loaded network segments:', Array.from(this.proxmoxConfig.networkSegments.keys()));
  }

  // Resume active matches after restart
  async resumeActiveMatches() {
    try {
      const activeMatches = await Match.findAll({
        where: { status: 'active' },
        include: [{ model: Team, as: 'teams' }]
      });

      for (const match of activeMatches) {
        console.log(`Resuming active match: ${match.name}`);
        
        this.activeMatches.set(match.id, {
          match,
          teams: match.teams,
          startTime: match.startTime,
          infrastructure: { networks: [], vms: [], monitoring: {} }
        });

        // Resume scoring service
        await scoringService.startMatchScoring(match.id);

        // Resume timer if needed
        if (match.duration && match.startTime) {
          const elapsed = Date.now() - match.startTime.getTime();
          const remaining = (match.duration * 60 * 1000) - elapsed;
          
          if (remaining > 0) {
            this.setupMatchTimer(match.id, remaining / 1000 / 60);
          } else {
            // Match should have ended
            await this.endMatch(match.id, null, 'time_expired');
          }
        }
      }

      console.log(`Resumed ${activeMatches.length} active matches`);
    } catch (error) {
      console.error('Error resuming active matches:', error);
    }
  }

  // Get default configurations
  getDefaultNetworkConfig() {
    return {
      isolation: true,
      allowInterTeamCommunication: false,
      allowInternetAccess: false,
      networkSegmentation: true,
      monitorTraffic: true
    };
  }

  getDefaultVMConfig() {
    // Use actual available VMs from the Proxmox environment
    return {
      templates: [
        { templateId: 102, name: 'Win-26.128', role: 'target' },
        { templateId: 101, name: 'kali-26.128', role: 'attacker' }
      ],
      autoStart: false, // Don't auto-start existing VMs
      resourceLimits: {
        cpu: 2,
        memory: 2048,
        disk: 20
      },
      reuseExistingVMs: true, // Flag to indicate we're reusing existing VMs
      networkReconfiguration: true // VMs will need network reconfiguration
    };
  }

  getDefaultScoringRules() {
    return {
      autoScoring: true,
      confidenceThreshold: 0.7,
      pointValues: {
        'network_compromise': 25,
        'vulnerability_exploit': 30,
        'attack_success': 50,
        'lateral_movement': 35,
        'flag_capture': 100
      },
      penaltyRules: {
        'detection_evasion': -10,
        'service_disruption': -25
      }
    };
  }

  // Clean up match infrastructure
  async cleanupMatchInfrastructure(matchId) {
    try {
      const matchData = this.activeMatches.get(matchId);
      if (!matchData) return;

      console.log(`Cleaning up infrastructure for match ${matchId}`);

      // VMs are already stopped and released by endMatch()
      // Just clean up network rules
      for (const network of matchData.infrastructure.networks) {
        try {
          await this.executeCommand(`iptables -D FORWARD -s ${network.subnet} -d ${network.subnet} -j ACCEPT`);
        } catch (error) {
          console.warn(`Failed to remove firewall rule for ${network.subnet}`);
        }
      }

      console.log(`✅ Infrastructure cleanup completed for match ${matchId}`);
    } catch (error) {
      console.error('Error cleaning up match infrastructure:', error);
    }
  }
}

module.exports = new GameEngine();

const axios = require('axios');
const { Match, Team, ScoringEvent } = require('../models');

class ELKIntegrationService {
  constructor() {
    this.elasticsearchUrl = process.env.ELASTICSEARCH_URL || 'http://172.16.200.136:9200';
    this.kibanaUrl = process.env.KIBANA_URL || 'http://172.16.200.136:5601';
    this.logstashUrl = process.env.LOGSTASH_URL || 'http://172.16.200.136:5044';
    this.enablePacketAnalysis = process.env.ENABLE_PACKET_ANALYSIS === 'true';
    this.enableAutoScoring = process.env.ENABLE_AUTO_SCORING === 'true';
    this.enableRealTimeScoring = process.env.ENABLE_REAL_TIME_SCORING === 'true';
  }

  /**
   * Initialize ELK integration for a match
   */
  async initializeMatch(matchId) {
    try {
      const match = await Match.findByPk(matchId);
      if (!match) {
        throw new Error(`Match ${matchId} not found`);
      }

      console.log(`Initializing ELK integration for match ${matchId}`);

      // Create index pattern for the match
      const indexPattern = `cyberwar-${matchId}-*`;
      await this.createIndexPattern(indexPattern, match.name);

      // Set up packet analysis if enabled
      if (this.enablePacketAnalysis) {
        await this.setupPacketAnalysis(matchId, match.networkConfig);
      }

      // Set up real-time scoring if enabled
      if (this.enableRealTimeScoring) {
        await this.setupRealTimeScoring(matchId);
      }

      console.log(`✅ ELK integration initialized for match ${matchId}`);

    } catch (error) {
      console.error(`Error initializing ELK integration for match ${matchId}:`, error);
    }
  }

  /**
   * Create Elasticsearch index pattern
   */
  async createIndexPattern(pattern, matchName) {
    try {
      const response = await axios.post(`${this.elasticsearchUrl}/_index_template/cyberwar-${pattern}`, {
        index_patterns: [pattern],
        template: {
          settings: {
            number_of_shards: 1,
            number_of_replicas: 0
          },
          mappings: {
            properties: {
              timestamp: { type: 'date' },
              source_ip: { type: 'ip' },
              dest_ip: { type: 'ip' },
              protocol: { type: 'keyword' },
              port: { type: 'integer' },
              payload: { type: 'text' },
              event_type: { type: 'keyword' },
              team_id: { type: 'keyword' },
              match_id: { type: 'keyword' },
              vulnerability: { type: 'keyword' },
              severity: { type: 'keyword' }
            }
          }
        }
      });

      console.log(`✅ Created index pattern: ${pattern}`);
      return response.data;

    } catch (error) {
      console.error(`Error creating index pattern ${pattern}:`, error);
    }
  }

  /**
   * Set up packet analysis
   */
  async setupPacketAnalysis(matchId, networkConfig) {
    try {
      console.log(`Setting up packet analysis for match ${matchId}`);

      // Create packet capture configuration
      const packetConfig = {
        match_id: matchId,
        target_subnet: networkConfig.targetSubnet,
        attacker_subnet: networkConfig.attackerSubnet,
        target_vm: networkConfig.targetVM,
        attacker_vms: networkConfig.attackerVMs,
        capture_filters: [
          `host ${networkConfig.targetVM}`,
          `net ${networkConfig.targetSubnet}`,
          `net ${networkConfig.attackerSubnet}`
        ]
      };

      // Send configuration to Logstash
      await axios.post(`${this.logstashUrl}/packet-analysis`, packetConfig);

      console.log(`✅ Packet analysis configured for match ${matchId}`);

    } catch (error) {
      console.error(`Error setting up packet analysis for match ${matchId}:`, error);
    }
  }

  /**
   * Set up real-time scoring
   */
  async setupRealTimeScoring(matchId) {
    try {
      console.log(`Setting up real-time scoring for match ${matchId}`);

      // Create scoring rules in Elasticsearch
      const scoringRules = {
        vulnerability_patterns: [
          {
            pattern: 'ms17-010',
            points: 200,
            description: 'MS17-010 EternalBlue vulnerability'
          },
          {
            pattern: 'smb_v1',
            points: 50,
            description: 'SMB version 1 enabled'
          },
          {
            pattern: 'weak_password',
            points: 150,
            description: 'Weak password detected'
          },
          {
            pattern: 'port_scan',
            points: 75,
            description: 'Port scanning activity'
          },
          {
            pattern: 'exploit_attempt',
            points: 100,
            description: 'Exploitation attempt detected'
          }
        ]
      };

      await axios.post(`${this.elasticsearchUrl}/cyberwar-${matchId}-scoring/_doc`, {
        timestamp: new Date().toISOString(),
        match_id: matchId,
        scoring_rules: scoringRules
      });

      console.log(`✅ Real-time scoring configured for match ${matchId}`);

    } catch (error) {
      console.error(`Error setting up real-time scoring for match ${matchId}:`, error);
    }
  }

  /**
   * Analyze packets for vulnerability detection
   */
  async analyzePackets(matchId) {
    try {
      const indexPattern = `cyberwar-${matchId}-*`;
      
      // Query Elasticsearch for recent packets
      const response = await axios.post(`${this.elasticsearchUrl}/${indexPattern}/_search`, {
        query: {
          bool: {
            must: [
              { range: { timestamp: { gte: 'now-30s' } } },
              { term: { match_id: matchId } }
            ]
          }
        },
        size: 100,
        sort: [{ timestamp: { order: 'desc' } }]
      });

      const packets = response.data.hits.hits;
      
      // Analyze packets for vulnerabilities
      for (const packet of packets) {
        await this.analyzePacket(packet._source, matchId);
      }

    } catch (error) {
      console.error(`Error analyzing packets for match ${matchId}:`, error);
    }
  }

  /**
   * Analyze individual packet for vulnerabilities
   */
  async analyzePacket(packet, matchId) {
    try {
      const vulnerabilities = [];

      // Check for MS17-010 patterns
      if (packet.payload && packet.payload.includes('SMB')) {
        if (packet.payload.includes('NT LM 0.12') || packet.payload.includes('SMBv1')) {
          vulnerabilities.push({
            type: 'smb_v1',
            points: 50,
            description: 'SMB version 1 detected'
          });
        }
      }

      // Check for exploitation attempts
      if (packet.payload && (
        packet.payload.includes('eternalblue') ||
        packet.payload.includes('ms17-010') ||
        packet.payload.includes('CVE-2017-0144')
      )) {
        vulnerabilities.push({
          type: 'ms17-010',
          points: 200,
          description: 'MS17-010 exploitation attempt detected'
        });
      }

      // Check for port scanning
      if (packet.event_type === 'port_scan') {
        vulnerabilities.push({
          type: 'port_scan',
          points: 75,
          description: 'Port scanning activity detected'
        });
      }

      // Check for brute force attempts
      if (packet.event_type === 'auth_failure' && packet.failure_count > 5) {
        vulnerabilities.push({
          type: 'weak_password',
          points: 150,
          description: 'Multiple authentication failures detected'
        });
      }

      // Award points for vulnerabilities
      for (const vuln of vulnerabilities) {
        await this.awardPointsForVulnerability(matchId, vuln, packet);
      }

    } catch (error) {
      console.error('Error analyzing packet:', error);
    }
  }

  /**
   * Award points for vulnerability detection
   */
  async awardPointsForVulnerability(matchId, vulnerability, packet) {
    try {
      const match = await Match.findByPk(matchId, {
        include: [{ model: Team, as: 'teams' }]
      });

      if (!match || match.status !== 'active') {
        return;
      }

      // Determine which team gets points based on source IP
      const sourceIP = packet.source_ip;
      const teams = await match.getTeams();
      
      // Find team that owns the source IP (simplified logic)
      const winningTeam = teams[0]; // For now, award to first team

      if (winningTeam) {
        // Create scoring event
        await ScoringEvent.create({
          matchId: matchId,
          teamId: winningTeam.id,
          eventType: 'packet_analysis',
          points: vulnerability.points,
          description: vulnerability.description,
          metadata: {
            vulnerability: vulnerability.type,
            source_ip: packet.source_ip,
            dest_ip: packet.dest_ip,
            protocol: packet.protocol,
            timestamp: packet.timestamp
          }
        });

        // Update team points
        await winningTeam.increment('currentPoints', { by: vulnerability.points });

        console.log(`✅ Awarded ${vulnerability.points} points to ${winningTeam.name} for ${vulnerability.type}`);

        // Send real-time update
        this.sendRealTimeUpdate(matchId, {
          type: 'vulnerability_detected',
          team: winningTeam.name,
          vulnerability: vulnerability.type,
          points: vulnerability.points,
          description: vulnerability.description
        });
      }

    } catch (error) {
      console.error('Error awarding points for vulnerability:', error);
    }
  }

  /**
   * Get match analytics from Kibana
   */
  async getMatchAnalytics(matchId) {
    try {
      const indexPattern = `cyberwar-${matchId}-*`;
      
      // Get basic statistics
      const statsResponse = await axios.post(`${this.elasticsearchUrl}/${indexPattern}/_search`, {
        size: 0,
        aggs: {
          total_packets: { value_count: { field: '_id' } },
          vulnerabilities: {
            terms: { field: 'vulnerability.keyword', size: 10 }
          },
          top_teams: {
            terms: { field: 'team_id.keyword', size: 5 }
          },
          time_series: {
            date_histogram: {
              field: 'timestamp',
              interval: '1m'
            }
          }
        }
      });

      return statsResponse.data.aggregations;

    } catch (error) {
      console.error(`Error getting analytics for match ${matchId}:`, error);
      return null;
    }
  }

  /**
   * Send real-time updates
   */
  sendRealTimeUpdate(matchId, data) {
    // This would integrate with your WebSocket service
    console.log(`Real-time update for match ${matchId}:`, data);
  }

  /**
   * Create Kibana dashboard
   */
  async createDashboard(matchId, matchName) {
    try {
      const dashboardConfig = {
        title: `CyberWar Match: ${matchName}`,
        index_pattern: `cyberwar-${matchId}-*`,
        panels: [
          {
            title: 'Packet Analysis',
            type: 'visualization',
            visualization: {
              type: 'line',
              params: {
                index_pattern: `cyberwar-${matchId}-*`,
                time_field: 'timestamp'
              }
            }
          },
          {
            title: 'Vulnerability Distribution',
            type: 'visualization',
            visualization: {
              type: 'pie',
              params: {
                index_pattern: `cyberwar-${matchId}-*`,
                field: 'vulnerability.keyword'
              }
            }
          },
          {
            title: 'Team Performance',
            type: 'visualization',
            visualization: {
              type: 'bar',
              params: {
                index_pattern: `cyberwar-${matchId}-*`,
                field: 'team_id.keyword'
              }
            }
          }
        ]
      };

      // This would create a Kibana dashboard
      console.log(`Dashboard configuration for match ${matchId}:`, dashboardConfig);

    } catch (error) {
      console.error(`Error creating dashboard for match ${matchId}:`, error);
    }
  }
}

module.exports = new ELKIntegrationService();
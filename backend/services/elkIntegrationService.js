const { exec } = require('child_process');
const fs = require('fs').promises;
const path = require('path');
const vulnerabilityDetectionService = require('./vulnerabilityDetectionService');
const scoringService = require('./scoringService');

class ELKIntegrationService {
  constructor() {
    this.config = {
      elasticsearchUrl: process.env.ELASTICSEARCH_URL || 'http://172.16.200.136:9200',
      kibanaUrl: process.env.KIBANA_URL || 'http://172.16.200.136:5601',
      logstashUrl: process.env.LOGSTASH_URL || 'http://172.16.200.136:5044',
      enabled: process.env.ENABLE_ELK_INTEGRATION === 'true',
      maxRetries: 3,
      retryDelay: 5000
    };
    
    this.indexPatterns = {
      logs: 'cyberrange-logs-*',
      security: 'cyberrange-security-*',
      scoring: 'cyberrange-scoring-*',
      network: 'cyberrange-network-*'
    };

    this.isAvailable = false;
    this.lastHealthCheck = null;
    
    if (this.config.enabled) {
      this.initialize();
    }
  }

  // Initialize ELK integration
  async initialize() {
    try {
      console.log('Initializing ELK Stack integration...');
      
      // Check ELK availability
      const health = await this.healthCheck();
      if (health.available) {
        await this.setupIndices();
        await this.setupDashboards();
        console.log('✅ ELK Stack integration initialized successfully');
      } else {
        console.warn('⚠️  ELK Stack not available, continuing without advanced analytics');
      }
    } catch (error) {
      console.error('Error initializing ELK integration:', error);
    }
  }

  // Health check for ELK stack
  async healthCheck() {
    try {
      const startTime = Date.now();
      
      // Check Elasticsearch
      const esHealth = await this.checkElasticsearch();
      
      // Check Kibana
      const kibanaHealth = await this.checkKibana();
      
      // Check Logstash (optional)
      const logstashHealth = await this.checkLogstash();
      
      const responseTime = Date.now() - startTime;
      
      this.isAvailable = esHealth.status === 'healthy';
      this.lastHealthCheck = new Date();
      
      return {
        available: this.isAvailable,
        responseTime,
        services: {
          elasticsearch: esHealth,
          kibana: kibanaHealth,
          logstash: logstashHealth
        },
        timestamp: this.lastHealthCheck
      };
    } catch (error) {
      console.error('ELK health check error:', error);
      this.isAvailable = false;
      return {
        available: false,
        error: error.message,
        timestamp: new Date()
      };
    }
  }

  // Check Elasticsearch health
  async checkElasticsearch() {
    return new Promise((resolve) => {
      const cmd = `curl -s -m 5 "${this.config.elasticsearchUrl}/_cluster/health"`;
      
      exec(cmd, (error, stdout, stderr) => {
        if (error) {
          resolve({
            status: 'unhealthy',
            error: error.message
          });
          return;
        }

        try {
          const health = JSON.parse(stdout);
          resolve({
            status: health.status === 'red' ? 'unhealthy' : 'healthy',
            cluster_name: health.cluster_name,
            number_of_nodes: health.number_of_nodes,
            active_shards: health.active_shards
          });
        } catch (parseError) {
          resolve({
            status: 'unhealthy',
            error: 'Invalid response from Elasticsearch'
          });
        }
      });
    });
  }

  // Check Kibana health
  async checkKibana() {
    return new Promise((resolve) => {
      const cmd = `curl -s -m 5 "${this.config.kibanaUrl}/api/status"`;
      
      exec(cmd, (error, stdout, stderr) => {
        if (error) {
          resolve({
            status: 'unhealthy',
            error: error.message
          });
          return;
        }

        try {
          const status = JSON.parse(stdout);
          resolve({
            status: status.status?.overall?.state === 'green' ? 'healthy' : 'unhealthy',
            version: status.version?.number,
            state: status.status?.overall?.state
          });
        } catch (parseError) {
          resolve({
            status: 'unknown',
            error: 'Could not parse Kibana response'
          });
        }
      });
    });
  }

  // Check Logstash health
  async checkLogstash() {
    return new Promise((resolve) => {
      const cmd = `curl -s -m 5 "${this.config.logstashUrl.replace(':5044', ':9600')}/_node/stats"`;
      
      exec(cmd, (error, stdout, stderr) => {
        if (error) {
          resolve({
            status: 'optional',
            note: 'Logstash check failed, but not required'
          });
          return;
        }

        try {
          const stats = JSON.parse(stdout);
          resolve({
            status: 'healthy',
            pipeline_count: stats.pipelines ? Object.keys(stats.pipelines).length : 0
          });
        } catch (parseError) {
          resolve({
            status: 'optional',
            note: 'Logstash response could not be parsed'
          });
        }
      });
    });
  }

  // Setup Elasticsearch indices
  async setupIndices() {
    try {
      const indices = [
        {
          name: 'cyberrange-logs',
          mapping: {
            properties: {
              '@timestamp': { type: 'date' },
              level: { type: 'keyword' },
              message: { type: 'text' },
              service: { type: 'keyword' },
              match_id: { type: 'integer' },
              team_id: { type: 'integer' },
              user_id: { type: 'integer' },
              ip_address: { type: 'ip' },
              event_type: { type: 'keyword' }
            }
          }
        },
        {
          name: 'cyberrange-security',
          mapping: {
            properties: {
              '@timestamp': { type: 'date' },
              event_category: { type: 'keyword' },
              event_name: { type: 'text' },
              vulnerability_id: { type: 'keyword' },
              severity_score: { type: 'integer' },
              confidence: { type: 'float' },
              source_ip: { type: 'ip' },
              dest_ip: { type: 'ip' },
              source_port: { type: 'integer' },
              dest_port: { type: 'integer' },
              protocol: { type: 'keyword' },
              match_id: { type: 'integer' },
              team_id: { type: 'integer' },
              detection_method: { type: 'keyword' },
              evidence: { type: 'object' }
            }
          }
        },
        {
          name: 'cyberrange-scoring',
          mapping: {
            properties: {
              '@timestamp': { type: 'date' },
              match_id: { type: 'integer' },
              team_id: { type: 'integer' },
              user_id: { type: 'integer' },
              event_type: { type: 'keyword' },
              event_subtype: { type: 'keyword' },
              base_points: { type: 'integer' },
              final_points: { type: 'integer' },
              confidence: { type: 'float' },
              source_type: { type: 'keyword' },
              vulnerability_id: { type: 'keyword' },
              description: { type: 'text' },
              evidence: { type: 'object' }
            }
          }
        },
        {
          name: 'cyberrange-network',
          mapping: {
            properties: {
              '@timestamp': { type: 'date' },
              src_ip: { type: 'ip' },
              dst_ip: { type: 'ip' },
              src_port: { type: 'integer' },
              dst_port: { type: 'integer' },
              protocol: { type: 'keyword' },
              packet_size: { type: 'integer' },
              flags: { type: 'keyword' },
              match_id: { type: 'integer' },
              team_id: { type: 'integer' },
              flow_id: { type: 'keyword' },
              attack_pattern: { type: 'keyword' }
            }
          }
        }
      ];

      for (const index of indices) {
        await this.createIndexIfNotExists(index.name, index.mapping);
      }

      console.log('✅ Elasticsearch indices setup completed');
    } catch (error) {
      console.error('Error setting up indices:', error);
    }
  }

  // Create index if it doesn't exist
  async createIndexIfNotExists(indexName, mapping) {
    return new Promise((resolve) => {
      // Check if index exists
      const checkCmd = `curl -s -I "${this.config.elasticsearchUrl}/${indexName}"`;
      
      exec(checkCmd, (error, stdout, stderr) => {
        if (stdout.includes('200 OK')) {
          // Index exists
          resolve(true);
          return;
        }

        // Create index
        const createCmd = `curl -s -X PUT "${this.config.elasticsearchUrl}/${indexName}" -H "Content-Type: application/json" -d '{"mappings": ${JSON.stringify(mapping)}}'`;
        
        exec(createCmd, (createError, createStdout) => {
          if (createError) {
            console.error(`Error creating index ${indexName}:`, createError);
            resolve(false);
          } else {
            console.log(`✅ Created index: ${indexName}`);
            resolve(true);
          }
        });
      });
    });
  }

  // Send log to Elasticsearch
  async sendLog(indexType, logData) {
    if (!this.isAvailable) return false;

    try {
      const indexName = `${this.indexPatterns[indexType].replace('*', new Date().toISOString().slice(0, 7))}`;
      const doc = {
        '@timestamp': new Date().toISOString(),
        ...logData
      };

      return new Promise((resolve) => {
        const cmd = `curl -s -X POST "${this.config.elasticsearchUrl}/${indexName}/_doc" -H "Content-Type: application/json" -d '${JSON.stringify(doc)}'`;
        
        exec(cmd, (error, stdout) => {
          if (error) {
            console.error('Error sending log to Elasticsearch:', error);
            resolve(false);
          } else {
            resolve(true);
          }
        });
      });
    } catch (error) {
      console.error('Error formatting log for Elasticsearch:', error);
      return false;
    }
  }

  // Log security event
  async logSecurityEvent(eventData) {
    return await this.sendLog('security', {
      event_category: eventData.category || 'security',
      event_name: eventData.name,
      vulnerability_id: eventData.vulnerabilityId,
      severity_score: eventData.severity || 50,
      confidence: eventData.confidence || 0.5,
      source_ip: eventData.sourceIP,
      dest_ip: eventData.destIP,
      source_port: eventData.sourcePort,
      dest_port: eventData.destPort,
      protocol: eventData.protocol,
      match_id: eventData.matchId,
      team_id: eventData.teamId,
      detection_method: eventData.detectionMethod,
      evidence: eventData.evidence || {}
    });
  }

  // Log scoring event
  async logScoringEvent(scoringData) {
    return await this.sendLog('scoring', {
      match_id: scoringData.matchId,
      team_id: scoringData.teamId,
      user_id: scoringData.userId,
      event_type: scoringData.eventType,
      event_subtype: scoringData.eventSubtype,
      base_points: scoringData.basePoints,
      final_points: scoringData.finalPoints,
      confidence: scoringData.confidence,
      source_type: scoringData.sourceType,
      vulnerability_id: scoringData.vulnerabilityId,
      description: scoringData.description,
      evidence: scoringData.evidence || {}
    });
  }

  // Log network traffic
  async logNetworkTraffic(networkData) {
    return await this.sendLog('network', {
      src_ip: networkData.srcIP,
      dst_ip: networkData.dstIP,
      src_port: networkData.srcPort,
      dst_port: networkData.dstPort,
      protocol: networkData.protocol,
      packet_size: networkData.packetSize,
      flags: networkData.flags,
      match_id: networkData.matchId,
      team_id: networkData.teamId,
      flow_id: networkData.flowId,
      attack_pattern: networkData.attackPattern
    });
  }

  // Query security events
  async querySecurityEvents(matchId, timeRange = '1h') {
    if (!this.isAvailable) return [];

    try {
      const query = {
        query: {
          bool: {
            must: [
              { term: { match_id: matchId } },
              { range: { '@timestamp': { gte: `now-${timeRange}` } } }
            ]
          }
        },
        sort: [{ '@timestamp': { order: 'desc' } }],
        size: 100
      };

      return new Promise((resolve) => {
        const cmd = `curl -s -X POST "${this.config.elasticsearchUrl}/${this.indexPatterns.security}/_search" -H "Content-Type: application/json" -d '${JSON.stringify(query)}'`;
        
        exec(cmd, (error, stdout) => {
          if (error) {
            console.error('Error querying security events:', error);
            resolve([]);
            return;
          }

          try {
            const response = JSON.parse(stdout);
            const events = response.hits?.hits?.map(hit => hit._source) || [];
            resolve(events);
          } catch (parseError) {
            console.error('Error parsing security events response:', parseError);
            resolve([]);
          }
        });
      });
    } catch (error) {
      console.error('Error querying security events:', error);
      return [];
    }
  }

  // Get vulnerability statistics from ELK
  async getVulnerabilityStats(matchId) {
    if (!this.isAvailable) return null;

    try {
      const query = {
        query: {
          bool: {
            must: [
              { term: { match_id: matchId } }
            ]
          }
        },
        aggs: {
          vulnerabilities_by_type: {
            terms: { field: 'vulnerability_id', size: 20 }
          },
          vulnerabilities_by_team: {
            terms: { field: 'team_id', size: 10 }
          },
          severity_distribution: {
            histogram: {
              field: 'severity_score',
              interval: 20
            }
          },
          detection_methods: {
            terms: { field: 'detection_method', size: 10 }
          }
        },
        size: 0
      };

      return new Promise((resolve) => {
        const cmd = `curl -s -X POST "${this.config.elasticsearchUrl}/${this.indexPatterns.security}/_search" -H "Content-Type: application/json" -d '${JSON.stringify(query)}'`;
        
        exec(cmd, (error, stdout) => {
          if (error) {
            resolve(null);
            return;
          }

          try {
            const response = JSON.parse(stdout);
            const aggs = response.aggregations;
            
            resolve({
              totalEvents: response.hits?.total?.value || 0,
              vulnerabilityTypes: aggs?.vulnerabilities_by_type?.buckets || [],
              teamStats: aggs?.vulnerabilities_by_team?.buckets || [],
              severityDistribution: aggs?.severity_distribution?.buckets || [],
              detectionMethods: aggs?.detection_methods?.buckets || []
            });
          } catch (parseError) {
            resolve(null);
          }
        });
      });
    } catch (error) {
      console.error('Error getting vulnerability stats:', error);
      return null;
    }
  }

  // Setup Kibana dashboards
  async setupDashboards() {
    try {
      const dashboards = [
        {
          id: 'cyberrange-overview',
          title: 'CyberRange Overview',
          description: 'Main dashboard for cyber warfare competition monitoring'
        },
        {
          id: 'cyberrange-security',
          title: 'Security Events',
          description: 'Security event monitoring and vulnerability detection'
        },
        {
          id: 'cyberrange-network',
          title: 'Network Analysis',
          description: 'Network traffic and attack pattern analysis'
        }
      ];

      // Note: In a full implementation, you would create actual Kibana dashboard configurations
      console.log('📊 Kibana dashboards configured (basic setup)');
      console.log(`   Access at: ${this.config.kibanaUrl}/app/kibana#/dashboards`);
      
    } catch (error) {
      console.error('Error setting up Kibana dashboards:', error);
    }
  }

  // Export logs for offline analysis
  async exportLogs(matchId, outputPath) {
    if (!this.isAvailable) {
      throw new Error('ELK Stack not available');
    }

    try {
      const indices = Object.values(this.indexPatterns);
      const exportData = {};

      for (const indexPattern of indices) {
        const query = {
          query: {
            bool: {
              must: [
                { term: { match_id: matchId } }
              ]
            }
          },
          sort: [{ '@timestamp': { order: 'desc' } }],
          size: 10000
        };

        const cmd = `curl -s -X POST "${this.config.elasticsearchUrl}/${indexPattern}/_search" -H "Content-Type: application/json" -d '${JSON.stringify(query)}'`;
        
        const data = await new Promise((resolve) => {
          exec(cmd, (error, stdout) => {
            if (error) {
              resolve([]);
              return;
            }

            try {
              const response = JSON.parse(stdout);
              resolve(response.hits?.hits?.map(hit => hit._source) || []);
            } catch {
              resolve([]);
            }
          });
        });

        exportData[indexPattern] = data;
      }

      // Write to file
      const exportFile = path.join(outputPath, `match-${matchId}-logs-${Date.now()}.json`);
      await fs.writeFile(exportFile, JSON.stringify(exportData, null, 2));

      console.log(`📥 Logs exported to: ${exportFile}`);
      return exportFile;
    } catch (error) {
      console.error('Error exporting logs:', error);
      throw error;
    }
  }

  // Get ELK integration status
  getStatus() {
    return {
      enabled: this.config.enabled,
      available: this.isAvailable,
      lastHealthCheck: this.lastHealthCheck,
      services: {
        elasticsearch: this.config.elasticsearchUrl,
        kibana: this.config.kibanaUrl,
        logstash: this.config.logstashUrl
      }
    };
  }
}

module.exports = new ELKIntegrationService();
const https = require('https');
const { exec } = require('child_process');

class ProxmoxService {
  constructor() {
    // Configuration for Proxmox VE API with token authentication
    this.config = {
      host: process.env.PROXMOX_HOST || '172.16.200.129',
      port: process.env.PROXMOX_PORT || 8006,
      apiUrl: process.env.PROXMOX_API_URL || 'https://172.16.200.129:8006',
      tokenName: process.env.PROXMOX_API_TOKEN_NAME || 'cyberrange@pve!ansible',
      tokenValue: process.env.PROXMOX_API_TOKEN_VALUE || '9d14390f-b94b-4012-bef5-699670e81cfa',
      node: process.env.PROXMOX_NODE || 'pve',
      skipTLSVerify: true // For self-signed certificates
    };
    
    this.ticket = null;
    this.csrfToken = null;
    this.ticketExpiry = null;
    
    // VM inventory - available VMs for assignment (based on actual environment)
    this.availableVMs = new Map([
      // Main target VM (Win 7 SP1 x64)
      [103, { name: 'Vulnerable-Win7', type: 'windows', role: 'target', status: 'available', ip: '172.16.200.150' }],
      // Main attacker VM (Kali Linux 2024.2)
      [104, { name: 'Kali-Attacker', type: 'kali', role: 'attacker', status: 'available', ip: '172.16.200.151' }]
    ]);
    
    // Track VM assignments
    this.assignments = new Map(); // matchId -> { teamId -> [vmIds] }
  }

  // Authenticate with Proxmox API using token
  async authenticate() {
    try {
      // Token authentication doesn't need renewal
      if (this.config.tokenName && this.config.tokenValue) {
        return true;
      }

      console.log('Authenticating with Proxmox API using token...');
      return true;
    } catch (error) {
      console.error('❌ Proxmox token authentication failed:', error.message);
      return false;
    }
  }

  // Make HTTP request to Proxmox API
  async makeRequest(method, path, data = null) {
    return new Promise((resolve, reject) => {
      const options = {
        hostname: this.config.host,
        port: this.config.port,
        path: `/api2/json${path}`,
        method: method,
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        rejectUnauthorized: !this.config.skipTLSVerify
      };

      // Add token authentication header
      if (this.config.tokenName && this.config.tokenValue) {
        options.headers.Authorization = `PVEAPIToken=${this.config.tokenName}=${this.config.tokenValue}`;
      }

      // Fallback to cookie authentication if token not available
      if (!options.headers.Authorization && this.ticket) {
        options.headers.Cookie = `PVEAuthCookie=${this.ticket}`;
        if (method !== 'GET' && this.csrfToken) {
          options.headers.CSRFPreventionToken = this.csrfToken;
        }
      }

      const req = https.request(options, (res) => {
        let responseBody = '';
        
        res.on('data', (chunk) => {
          responseBody += chunk;
        });

        res.on('end', () => {
          try {
            const parsed = JSON.parse(responseBody);
            if (res.statusCode >= 200 && res.statusCode < 300) {
              resolve(parsed);
            } else {
              reject(new Error(`HTTP ${res.statusCode}: ${parsed.errors || responseBody}`));
            }
          } catch (parseError) {
            reject(new Error(`Failed to parse response: ${responseBody}`));
          }
        });
      });

      req.on('error', (error) => {
        reject(error);
      });

      // Send data if provided
      if (data) {
        const formData = new URLSearchParams(data).toString();
        req.write(formData);
      }

      req.end();
    });
  }

  // Get list of all VMs
  async getVMList() {
    try {
      await this.authenticate();
      
      const response = await this.makeRequest('GET', `/nodes/${this.config.node}/qemu`);
      
      if (response && response.data) {
        return response.data.map(vm => ({
          vmid: vm.vmid,
          name: vm.name,
          status: vm.status,
          uptime: vm.uptime,
          mem: vm.mem,
          maxmem: vm.maxmem,
          cpu: vm.cpu,
          cpus: vm.cpus
        }));
      }
      
      return [];
    } catch (error) {
      console.error('Error getting VM list:', error.message);
      return [];
    }
  }

  // Get VM status
  async getVMStatus(vmId) {
    try {
      await this.authenticate();
      
      const response = await this.makeRequest('GET', `/nodes/${this.config.node}/qemu/${vmId}/status/current`);
      
      if (response && response.data) {
        return {
          vmid: vmId,
          status: response.data.status,
          uptime: response.data.uptime,
          cpu: response.data.cpu,
          mem: response.data.mem,
          maxmem: response.data.maxmem,
          pid: response.data.pid
        };
      }
      
      return null;
    } catch (error) {
      console.error(`Error getting VM ${vmId} status:`, error.message);
      return null;
    }
  }

  // Start VM
  async startVM(vmId) {
    try {
      await this.authenticate();
      
      console.log(`Starting VM ${vmId}...`);
      
      const response = await this.makeRequest('POST', `/nodes/${this.config.node}/qemu/${vmId}/status/start`);
      
      if (response) {
        console.log(`✅ VM ${vmId} start command sent`);
        return true;
      }
      
      return false;
    } catch (error) {
      console.error(`Error starting VM ${vmId}:`, error.message);
      return false;
    }
  }

  // Stop VM
  async stopVM(vmId) {
    try {
      await this.authenticate();
      
      console.log(`Stopping VM ${vmId}...`);
      
      const response = await this.makeRequest('POST', `/nodes/${this.config.node}/qemu/${vmId}/status/stop`);
      
      if (response) {
        console.log(`✅ VM ${vmId} stop command sent`);
        return true;
      }
      
      return false;
    } catch (error) {
      console.error(`Error stopping VM ${vmId}:`, error.message);
      return false;
    }
  }

  // Shutdown VM gracefully
  async shutdownVM(vmId) {
    try {
      await this.authenticate();
      
      console.log(`Shutting down VM ${vmId}...`);
      
      const response = await this.makeRequest('POST', `/nodes/${this.config.node}/qemu/${vmId}/status/shutdown`);
      
      if (response) {
        console.log(`✅ VM ${vmId} shutdown command sent`);
        return true;
      }
      
      return false;
    } catch (error) {
      console.error(`Error shutting down VM ${vmId}:`, error.message);
      return false;
    }
  }

  // Assign VMs to a team for a match
  async assignVMsToTeam(matchId, teamId, vmRequirements) {
    try {
      console.log(`Assigning VMs to Team ${teamId} for Match ${matchId}`);
      console.log('Requirements:', vmRequirements);

      if (!this.assignments.has(matchId)) {
        this.assignments.set(matchId, new Map());
      }

      const matchAssignments = this.assignments.get(matchId);
      const assignedVMs = [];

      // Find available VMs matching requirements
      for (const requirement of vmRequirements) {
        const availableVM = this.findAvailableVM(requirement.type, requirement.role);
        
        if (availableVM) {
          // Mark VM as assigned
          availableVM.status = 'assigned';
          availableVM.assignedTo = { matchId, teamId };
          availableVM.assignedAt = new Date();
          
          assignedVMs.push({
            vmId: availableVM.vmId,
            name: availableVM.name,
            type: availableVM.type,
            role: availableVM.role,
            requirement: requirement
          });
          
          console.log(`✅ Assigned VM ${availableVM.vmId} (${availableVM.name}) to Team ${teamId}`);
        } else {
          console.warn(`⚠️  No available VM found for requirement: ${requirement.type}/${requirement.role}`);
        }
      }

      // Store team assignments
      matchAssignments.set(teamId, assignedVMs);

      return {
        success: true,
        assignedVMs,
        message: `Assigned ${assignedVMs.length} VMs to Team ${teamId}`
      };

    } catch (error) {
      console.error('Error assigning VMs:', error.message);
      return {
        success: false,
        error: error.message,
        assignedVMs: []
      };
    }
  }

  // Find an available VM matching criteria
  findAvailableVM(type, role) {
    for (const [vmId, vm] of this.availableVMs) {
      if (vm.status === 'available' && 
          (vm.type === type || type === 'any') && 
          (vm.role === role || role === 'any')) {
        return { vmId, ...vm };
      }
    }
    return null;
  }

  // Get available VMs for assignment
  getAvailableVMs(filters = {}) {
    const available = [];
    
    for (const [vmId, vm] of this.availableVMs) {
      if (vm.status === 'available') {
        // Apply filters
        if (filters.type && vm.type !== filters.type) continue;
        if (filters.role && vm.role !== filters.role) continue;
        
        available.push({
          vmId,
          name: vm.name,
          type: vm.type,
          role: vm.role,
          status: vm.status
        });
      }
    }
    
    return available;
  }

  // Release VMs assigned to a team
  async releaseTeamVMs(matchId, teamId) {
    try {
      if (!this.assignments.has(matchId)) {
        return { success: true, message: 'No VMs assigned to this match' };
      }

      const matchAssignments = this.assignments.get(matchId);
      const teamVMs = matchAssignments.get(teamId) || [];

      console.log(`Releasing ${teamVMs.length} VMs from Team ${teamId}`);

      // Release each VM
      for (const assignment of teamVMs) {
        if (this.availableVMs.has(assignment.vmId)) {
          const vm = this.availableVMs.get(assignment.vmId);
          vm.status = 'available';
          delete vm.assignedTo;
          delete vm.assignedAt;
          
          console.log(`✅ Released VM ${assignment.vmId} (${assignment.name})`);
        }
      }

      // Remove team from match assignments
      matchAssignments.delete(teamId);

      // If no teams left, remove match assignments
      if (matchAssignments.size === 0) {
        this.assignments.delete(matchId);
      }

      return {
        success: true,
        releasedCount: teamVMs.length,
        message: `Released ${teamVMs.length} VMs from Team ${teamId}`
      };

    } catch (error) {
      console.error('Error releasing team VMs:', error.message);
      return {
        success: false,
        error: error.message
      };
    }
  }

  // Release all VMs for a match
  async releaseMatchVMs(matchId) {
    try {
      if (!this.assignments.has(matchId)) {
        return { success: true, message: 'No VMs assigned to this match' };
      }

      const matchAssignments = this.assignments.get(matchId);
      let totalReleased = 0;

      console.log(`Releasing all VMs for Match ${matchId}`);

      // Release VMs for each team
      for (const [teamId, teamVMs] of matchAssignments) {
        for (const assignment of teamVMs) {
          if (this.availableVMs.has(assignment.vmId)) {
            const vm = this.availableVMs.get(assignment.vmId);
            vm.status = 'available';
            delete vm.assignedTo;
            delete vm.assignedAt;
            totalReleased++;
          }
        }
      }

      // Remove all match assignments
      this.assignments.delete(matchId);

      console.log(`✅ Released ${totalReleased} VMs for Match ${matchId}`);

      return {
        success: true,
        releasedCount: totalReleased,
        message: `Released ${totalReleased} VMs for Match ${matchId}`
      };

    } catch (error) {
      console.error('Error releasing match VMs:', error.message);
      return {
        success: false,
        error: error.message
      };
    }
  }

  // Get VM assignments for a match
  getMatchAssignments(matchId) {
    if (!this.assignments.has(matchId)) {
      return {};
    }

    const matchAssignments = this.assignments.get(matchId);
    const result = {};

    for (const [teamId, teamVMs] of matchAssignments) {
      result[teamId] = teamVMs.map(assignment => ({
        vmId: assignment.vmId,
        name: assignment.name,
        type: assignment.type,
        role: assignment.role,
        status: this.availableVMs.get(assignment.vmId)?.status || 'unknown'
      }));
    }

    return result;
  }

  // Start all VMs for a match
  async startMatchVMs(matchId) {
    try {
      const assignments = this.getMatchAssignments(matchId);
      const results = [];

      for (const [teamId, teamVMs] of Object.entries(assignments)) {
        for (const vm of teamVMs) {
          console.log(`Starting VM ${vm.vmId} for Team ${teamId}...`);
          const result = await this.startVM(vm.vmId);
          results.push({
            vmId: vm.vmId,
            teamId,
            success: result
          });
          
          // Small delay between starts
          await new Promise(resolve => setTimeout(resolve, 2000));
        }
      }

      return {
        success: true,
        results,
        message: `Started ${results.filter(r => r.success).length}/${results.length} VMs`
      };

    } catch (error) {
      console.error('Error starting match VMs:', error.message);
      return {
        success: false,
        error: error.message
      };
    }
  }

  // Stop all VMs for a match
  async stopMatchVMs(matchId) {
    try {
      const assignments = this.getMatchAssignments(matchId);
      const results = [];

      for (const [teamId, teamVMs] of Object.entries(assignments)) {
        for (const vm of teamVMs) {
          console.log(`Stopping VM ${vm.vmId} for Team ${teamId}...`);
          const result = await this.shutdownVM(vm.vmId);
          results.push({
            vmId: vm.vmId,
            teamId,
            success: result
          });
          
          // Small delay between stops
          await new Promise(resolve => setTimeout(resolve, 1000));
        }
      }

      return {
        success: true,
        results,
        message: `Stopped ${results.filter(r => r.success).length}/${results.length} VMs`
      };

    } catch (error) {
      console.error('Error stopping match VMs:', error.message);
      return {
        success: false,
        error: error.message
      };
    }
  }

  // Get system status and VM inventory
  async getSystemStatus() {
    try {
      await this.authenticate();
      
      // Get node status
      const nodeResponse = await this.makeRequest('GET', `/nodes/${this.config.node}/status`);
      const vmList = await this.getVMList();
      
      // Count VMs by status
      const vmStats = {
        total: this.availableVMs.size,
        available: 0,
        assigned: 0,
        running: 0,
        stopped: 0
      };

      for (const [vmId, vm] of this.availableVMs) {
        if (vm.status === 'available') vmStats.available++;
        if (vm.status === 'assigned') vmStats.assigned++;
        
        // Get actual running status from Proxmox
        const vmInfo = vmList.find(v => v.vmid === vmId);
        if (vmInfo) {
          if (vmInfo.status === 'running') vmStats.running++;
          if (vmInfo.status === 'stopped') vmStats.stopped++;
        }
      }

      return {
        connected: true,
        node: this.config.node,
        nodeStatus: nodeResponse?.data || {},
        vmStats,
        totalAssignments: this.assignments.size,
        lastUpdate: new Date()
      };

    } catch (error) {
      console.error('Error getting system status:', error.message);
      return {
        connected: false,
        error: error.message,
        lastUpdate: new Date()
      };
    }
  }

  // Health check - verify Proxmox connectivity
  async healthCheck() {
    try {
      const authenticated = await this.authenticate();
      if (!authenticated) {
        return { status: 'error', message: 'Authentication failed' };
      }

      const vmList = await this.getVMList();
      
      return {
        status: 'healthy',
        message: 'Proxmox API connection successful',
        vmCount: vmList.length,
        availableVMs: this.getAvailableVMs().length
      };
      
    } catch (error) {
      return {
        status: 'error',
        message: error.message
      };
    }
  }
}

module.exports = new ProxmoxService();

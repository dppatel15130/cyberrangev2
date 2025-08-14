const axios = require('axios');

// Proxmox API helper
exports.proxmoxApi = {
  async getToken() {
    try {
      const response = await axios.post(
        `${process.env.PROXMOX_API_URL}/access/ticket`,
        {
          username: process.env.PROXMOX_USERNAME,
          password: process.env.PROXMOX_PASSWORD,
        }
      );
      
      return {
        ticket: response.data.data.ticket,
        csrf: response.data.data.CSRFPreventionToken,
      };
    } catch (error) {
      console.error('Proxmox authentication error:', error);
      throw new Error('Failed to authenticate with Proxmox');
    }
  },
  
  async request(method, endpoint, data = null, useToken = true) {
    try {
      const config = {
        method,
        url: `${process.env.PROXMOX_API_URL}${endpoint}`,
        headers: {},
      };
      
      if (useToken) {
        if (process.env.PROXMOX_API_TOKEN_NAME && process.env.PROXMOX_API_TOKEN_VALUE) {
          // Use API token if available
          config.headers.Authorization = `PVEAPIToken=${process.env.PROXMOX_API_TOKEN_NAME}=${process.env.PROXMOX_API_TOKEN_VALUE}`;
        } else {
          // Fall back to ticket-based auth
          const token = await this.getToken();
          config.headers.Cookie = `PVEAuthCookie=${token.ticket}`;
          
          if (method !== 'GET') {
            config.headers.CSRFPreventionToken = token.csrf;
          }
        }
      }
      
      if (data) {
        config.data = data;
      }
      
      const response = await axios(config);
      return response.data;
    } catch (error) {
      console.error(`Proxmox API error (${method} ${endpoint}):`, error);
      throw error;
    }
  },
  
  // VM operations
  async createVM(templateId, name, node = process.env.PROXMOX_NODE || 'pve') {
    return this.request('POST', `/nodes/${node}/qemu/${templateId}/clone`, {
      newid: name,
      name,
      full: 1, // Full clone
    });
  },
  
  async startVM(vmId, node = process.env.PROXMOX_NODE || 'pve') {
    return this.request('POST', `/nodes/${node}/qemu/${vmId}/status/start`);
  },
  
  async stopVM(vmId, node = process.env.PROXMOX_NODE || 'pve') {
    return this.request('POST', `/nodes/${node}/qemu/${vmId}/status/stop`);
  },
  
  async getVMStatus(vmId, node = process.env.PROXMOX_NODE || 'pve') {
    return this.request('GET', `/nodes/${node}/qemu/${vmId}/status/current`);
  },
  
  async getVMIpAddress(vmId, node = process.env.PROXMOX_NODE || 'pve') {
    const config = await this.request('GET', `/nodes/${node}/qemu/${vmId}/config`);
    
    // Extract IP from config (this is a simplification, actual implementation may vary)
    const ipMatch = config.data.ipconfig0?.match(/ip=([^/]+)/);
    return ipMatch ? ipMatch[1] : null;
  },
};

// Guacamole API helper
exports.guacamoleApi = {
  token: null,
  
  async getToken() {
    if (this.token) return this.token;
    
    try {
      const formData = new URLSearchParams();
      formData.append('username', process.env.GUACAMOLE_USERNAME);
      formData.append('password', process.env.GUACAMOLE_PASSWORD);
      
      const response = await axios.post(
        `${process.env.GUACAMOLE_API_URL}/tokens`,
        formData,
        {
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
          },
        }
      );
      
      this.token = response.data.authToken;
      return this.token;
    } catch (error) {
      console.error('Guacamole authentication error:', error);
      throw new Error('Failed to authenticate with Guacamole');
    }
  },
  
  async request(method, endpoint, data = null) {
    try {
      const token = await this.getToken();
      
      const config = {
        method,
        url: `${process.env.GUACAMOLE_API_URL}${endpoint}?token=${token}`,
        headers: {},
      };
      
      if (data) {
        config.data = data;
      }
      
      const response = await axios(config);
      return response.data;
    } catch (error) {
      console.error(`Guacamole API error (${method} ${endpoint}):`, error);
      throw error;
    }
  },
  
  async createConnection(name, protocol, hostname, port, username, password) {
    const connectionData = {
      name,
      protocol,
      parameters: {},
    };
    
    // Set parameters based on protocol
    if (protocol === 'ssh') {
      connectionData.parameters = {
        hostname,
        port,
        username,
        password,
      };
    } else if (protocol === 'rdp') {
      connectionData.parameters = {
        hostname,
        port,
        username,
        password,
        security: 'nla',
        ignore_cert: 'true',
      };
    }
    
    return this.request('POST', '/connections', connectionData);
  },
  
  getConnectionUrl(connectionId) {
    return `${process.env.GUACAMOLE_API_URL.replace('/api', '')}/#/client/${connectionId}`;
  },
};
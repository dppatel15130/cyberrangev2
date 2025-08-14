const axios = require('axios');
const https = require('https');
const { VM, User } = require('../models');
const { Op } = require('sequelize');
const labAutoStopService = require('../services/labAutoStopService');

// Configure HTTPS agent for self-signed certificates
const httpsAgent = new https.Agent({
  rejectUnauthorized: false
});

// Proxmox API configuration
const getProxmoxApiUrl = () => {
  const baseUrl = process.env.PROXMOX_API_URL || 'https://172.16.200.129:8006';
  // Ensure the base URL ends with /api2/json for Proxmox API calls
  return baseUrl.endsWith('/api2/json') ? baseUrl : `${baseUrl}/api2/json`;
};

// Create an Axios instance for Proxmox API interactions
const proxmoxApi = axios.create({
  baseURL: getProxmoxApiUrl(),
  headers: {
    // Construct Authorization header using Proxmox API token
    'Authorization': `PVEAPIToken=${process.env.PROXMOX_API_TOKEN_NAME || 'cyberrange@pve!ansible'}=${process.env.PROXMOX_API_TOKEN_VALUE || '9d14390f-b94b-4012-bef5-699670e81cfa'}`,
    'Content-Type': 'application/json',
    'Accept': 'application/json'
  },
  httpsAgent: httpsAgent, // Use the configured HTTPS agent
  timeout: 15000 // 15-second timeout for all Proxmox requests
});

// Guacamole API configuration
const guacamoleApi = {
  token: null, // Stores the authentication token for Guacamole

  /**
   * Retrieves or refreshes the Guacamole authentication token.
   * @returns {Promise<string>} The Guacamole authentication token.
   * @throws {Error} If authentication with Guacamole fails.
   */
  async getToken() {
    if (this.token) return this.token; // Return existing token if available
    try {
      console.log(`[DEBUG] Attempting to authenticate with Guacamole at ${process.env.GUACAMOLE_API_URL}/tokens`);
      const response = await axios.post(
        `${process.env.GUACAMOLE_API_URL}/tokens`, 
        {
          username: process.env.GUACAMOLE_USERNAME || 'guacadmin',
          password: process.env.GUACAMOLE_PASSWORD || 'guacadmin',
        }, 
        { 
          httpsAgent,
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
          },
          timeout: 10000 // 10 second timeout
        }
      );
      
      if (!response.data || !response.data.authToken) {
        throw new Error('No auth token received from Guacamole');
      }
      
      this.token = response.data.authToken;
      console.log('[DEBUG] Successfully authenticated with Guacamole');
      return this.token;
    } catch (error) {
      console.error('Guacamole authentication error:', {
        message: error.message,
        response: error.response?.data,
        status: error.response?.status,
        url: error.config?.url,
        method: error.config?.method,
        headers: error.config?.headers
      });
      throw new Error(`Failed to authenticate with Guacamole: ${error.message}`);
    }
  },

  /**
   * Creates a new user in Guacamole if they don't already exist.
   * @param {string} username The username to create.
   * @returns {Promise<object>} The Guacamole user object.
   * @throws {Error} If user creation fails.
   */
  async createUser(username) {
    try {
      if (!username) {
        throw new Error('Username is required to create Guacamole user');
      }
      
      const token = await this.getToken();
      const password = 'sac@1234'; // Default password for new Guacamole users
      
      console.log(`[DEBUG] Checking if Guacamole user '${username}' exists`);
      
      // Check if user already exists
      const existingUser = await axios.get(
        `${process.env.GUACAMOLE_API_URL}/session/data/mysql/users/${username}?token=${token}`,
        { 
          httpsAgent,
          headers: {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
          },
          timeout: 10000
        }
      ).catch(err => {
        // If user not found (404), return null to indicate it can be created
        if (err.response && err.response.status === 404) {
          console.log(`[INFO] Guacamole user '${username}' does not exist, will create`);
          return null;
        }
        console.error('Error checking existing Guacamole user:', {
          status: err.response?.status,
          data: err.response?.data,
          message: err.message
        });
        throw new Error(`Error checking existing user: ${err.message}`);
      });

      if (existingUser && existingUser.data) {
        console.log(`[INFO] Guacamole user '${username}' already exists.`);
        console.log(`[DEBUG] Existing user data:`, JSON.stringify(existingUser.data, null, 2));
        return existingUser.data;
      }

      console.log(`[DEBUG] Creating new Guacamole user '${username}'`);
      const response = await axios.post(
        `${process.env.GUACAMOLE_API_URL}/session/data/mysql/users?token=${token}`,
        { 
          username,
          password,
          attributes: {
            "disabled": "",
            "expired": "",
            "access-window-start": "",
            "access-window-end": "",
            "valid-from": "",
            "valid-until": "",
            "timezone": null
          }
        },
        { 
          httpsAgent,
          headers: {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
          },
          timeout: 10000
        }
      );
      
      if (!response.data) {
        throw new Error('No data received when creating Guacamole user');
      }
      
      console.log(`[INFO] Guacamole user '${username}' created successfully`);
      return response.data;
    } catch (error) {
      console.error('Guacamole create user error:', {
        message: error.message,
        response: error.response?.data,
        status: error.response?.status,
        config: {
          url: error.config?.url,
          method: error.config?.method,
          data: error.config?.data
        }
      });
      throw new Error(`Failed to create Guacamole user: ${error.message}`);
    }
  },

  /**
   * Creates a new VNC connection in Guacamole and grants the user permission to it.
   * @param {string} username The username to grant access to.
   * @param {string} connectionName The name for the new connection.
   * @param {string} ipAddress The IP address of the VM.
   * @returns {Promise<string>} The ID of the created Guacamole connection.
   * @throws {Error} If connection creation or permission assignment fails.
   */
  async createConnection(username, connectionName, ipAddress) {
    try {
      if (!username || !connectionName || !ipAddress) {
        throw new Error('Username, connection name, and IP address are required');
      }

      const token = await this.getToken();
      
      console.log(`[DEBUG] Creating new Guacamole VNC connection '${connectionName}' for ${ipAddress}:5900`);
      
      // First, create the connection
      const connectionResponse = await axios.post(
        `${process.env.GUACAMOLE_API_URL}/session/data/mysql/connections?token=${token}`,
        {
          name: connectionName,
          parentIdentifier: 'ROOT',
          protocol: 'vnc',
          parameters: {
            hostname: ipAddress,
            port: '5900',
            password: '123456', // VNC password
            username: '', // No username required
            'read-only': '',
            'swap-red-blue': '',
            'cursor': '',
            'color-depth': '32',
            'clipboard-encoding': 'UTF-8',
            'disable-copy': '',
            'disable-paste': '',
            'dest-port': '',
            'recording-exclude-output': 'true',
            'recording-exclude-mouse': 'false',
            'recording-include-keys': 'true',
            'create-recording-path': 'true',
            'enable-sftp': 'false',
            'sftp-port': '',
            'sftp-server-alive-interval': '',
            'enable-audio': 'false',
            'audio-servername': '',
            'sftp-hostname': '',
            'sftp-root-directory': '/',
            'sftp-username': '',
            'sftp-password': '',
            'sftp-private-key': '',
            'sftp-passphrase': '',
            'sftp-upload-directory': '',
            'sftp-public-key': '',
            'sftp-preferred-authentication': 'password',
            'sftp-host-key': '',
            'sftp-host-key-algorithm': 'auto'
          },
          attributes: {
            'max-connections': '1',
            'max-connections-per-user': '1',
            'weight': '1',
            'failover-only': '',
            'guacd-port': '4822',
            'guacd-hostname': 'guacd',
            'guacd-encryption': 'false',
            'recording-path': '',
            'recording-name': '${GUAC_USERNAME}-${GUAC_DATE}-${GUAC_TIME}',
            'recording-exclude-output': 'true',
            'recording-exclude-mouse': 'false',
            'recording-include-keys': 'true',
            'create-recording-path': 'true',
            'enable-sftp': 'false',
            'sftp-port': '22',
            'sftp-server-alive-interval': '0',
            'enable-audio': 'false',
            'sftp-root-directory': '/',
            'sftp-upload-directory': '',
            'sftp-passphrase': '',
            'sftp-private-key': '',
            'sftp-password': '',
            'sftp-username': '',
            'sftp-hostname': '',
            'sftp-public-key': '',
            'sftp-preferred-authentication': 'password',
            'sftp-host-key': '',
            'sftp-host-key-algorithm': 'auto',
            'color-depth': '32',
            'cursor': 'remote',
            'swap-red-blue': 'false',
            'read-only': 'false',
            'clipboard-encoding': 'UTF-8',
            'disable-copy': 'false',
            'disable-paste': 'false',
            'dest-port': '',
            'create-types': 'true',
            'enable-wallpaper': 'true',
            'enable-theming': 'true',
            'enable-font-smoothing': 'true',
            'enable-full-window-drag': 'true',
            'enable-desktop-composition': 'true',
            'enable-menu-animations': 'true',
            'disable-bitmap-caching': 'false',
            'disable-offscreen-caching': 'false',
            'disable-glyph-caching': 'false',
            'preconnection-id': '',
            'server-layout': '',
            'timezone': null,
            'console': 'false',
            'width': '1024',
            'height': '768',
            'dpi': '96',
            'resize-method': 'display-update',
            'normalize-clipboard': 'text',
            'console-audio': 'system',
            'disable-audio': 'false',
            'enable-audio-input': 'false',
            'enable-printing': 'false',
            'enable-drive': 'false',
            'drive-path': '',
            'create-drive-path': 'false',
            'enable-sftp': 'false',
            'sftp-hostname': '',
            'sftp-port': '22',
            'sftp-username': '',
            'sftp-password': '',
            'sftp-private-key': '',
            'sftp-passphrase': '',
            'sftp-root-directory': '/',
            'sftp-upload-directory': '',
            'sftp-public-key': '',
            'sftp-preferred-authentication': 'password',
            'sftp-host-key': '',
            'sftp-host-key-algorithm': 'auto',
            'sftp-server-alive-interval': '0',
            'enable-wallpaper': 'true',
            'enable-theming': 'true',
            'enable-font-smoothing': 'true',
            'enable-full-window-drag': 'true',
            'enable-desktop-composition': 'true',
            'enable-menu-animations': 'true',
            'disable-bitmap-caching': 'false',
            'disable-offscreen-caching': 'false',
            'disable-glyph-caching': 'false',
            'preconnection-id': '',
            'server-layout': '',
            'timezone': null,
            'console': 'false',
            'width': '1024',
            'height': '768',
            'dpi': '96',
            'resize-method': 'display-update',
            'normalize-clipboard': 'text',
            'console-audio': 'system',
            'disable-audio': 'false',
            'enable-audio-input': 'false',
            'enable-printing': 'false',
            'enable-drive': 'false',
            'drive-path': '',
            'create-drive-path': 'false',
            'security': 'any',
            'ignore-cert': 'true',
            'gateway-port': '',
            'server-alive-interval': '0',
            'backing-store': 'memory',
            'recording-path': '',
            'recording-name': '${GUAC_USERNAME}-${GUAC_DATE}-${GUAC_TIME}',
            'recording-exclude-output': 'true',
            'recording-exclude-mouse': 'false',
            'recording-include-keys': 'true',
            'create-recording-path': 'true',
            'enable-sftp': 'false',
            'sftp-port': '22',
            'sftp-server-alive-interval': '0',
            'enable-audio': 'false',
            'sftp-root-directory': '/',
            'sftp-upload-directory': '',
            'sftp-passphrase': '',
            'sftp-private-key': '',
            'sftp-password': '',
            'sftp-username': '',
            'sftp-hostname': '',
            'sftp-public-key': '',
            'sftp-preferred-authentication': 'password',
            'sftp-host-key': '',
            'sftp-host-key-algorithm': 'auto'
          }
        },
        { 
          httpsAgent,
          headers: {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
          },
          timeout: 10000
        }
      );

      console.log('[DEBUG] Guacamole createConnection response:', JSON.stringify(connectionResponse.data, null, 2));
      
      // Extract connection ID from the response
      const connectionId = connectionResponse.data?.identifier || 
                         connectionResponse.data?.object?.identifier || 
                         connectionResponse.data?.data?.identifier;
      
      if (!connectionId) {
        throw new Error(`Unable to retrieve connection identifier from Guacamole response: ${JSON.stringify(connectionResponse.data)}`);
      }

      console.log(`[INFO] Guacamole connection created with ID: ${connectionId}`);
      
      // Get the user's details to find their ID
      console.log(`[DEBUG] Getting user ID for '${username}'`);
      let userIdentifier;
      
      try {
        const userResponse = await axios.get(
          `${process.env.GUACAMOLE_API_URL}/session/data/mysql/users/${username}?token=${token}`,
          { 
            httpsAgent,
            headers: {
              'Content-Type': 'application/json',
              'Accept': 'application/json'
            },
            timeout: 10000
          }
        );
        
        console.log(`[DEBUG] User response data:`, JSON.stringify(userResponse.data, null, 2));
        
        // Try different possible locations for the user identifier
        userIdentifier = userResponse.data?.identifier || 
                        userResponse.data?.username || 
                        userResponse.data?.data?.identifier ||
                        userResponse.data?.data?.username ||
                        username; // Fallback to username itself
        
        console.log(`[DEBUG] Extracted user identifier: '${userIdentifier}'`);
        
      } catch (userError) {
        console.error('Error getting user details:', {
          message: userError.message,
          response: userError.response?.data,
          status: userError.response?.status
        });
        
        // If getting user details fails, try using the username directly as identifier
        console.log(`[WARN] Failed to get user details, using username '${username}' as identifier`);
        userIdentifier = username;
      }
      
      if (!userIdentifier) {
        throw new Error('Failed to get user identifier from Guacamole');
      }

      // Grant the user 'READ' permission to the newly created connection
      console.log(`[DEBUG] Granting READ permission to user '${username}' (ID: '${userIdentifier}') for connection '${connectionId}'`);
      
      try {
        await axios.patch(
          `${process.env.GUACAMOLE_API_URL}/session/data/mysql/users/${userIdentifier}/permissions?token=${token}`,
          [
            {
              op: 'add',
              path: `/connectionPermissions/${connectionId}`,
              value: 'READ'
            }
          ],
          { 
            httpsAgent,
            headers: {
              'Content-Type': 'application/json',
              'Accept': 'application/json'
            },
            timeout: 10000
          }
        );
        
        console.log(`[INFO] Successfully granted READ permission to user '${username}' for connection '${connectionId}'`);
        
      } catch (permissionError) {
        console.error('Error granting permissions:', {
          message: permissionError.message,
          response: permissionError.response?.data,
          status: permissionError.response?.status
        });
        
        // Try alternative permission granting method
        console.log(`[DEBUG] Trying alternative permission method for user '${username}'`);
        
        try {
          // Alternative: Try using username instead of userIdentifier
          await axios.patch(
            `${process.env.GUACAMOLE_API_URL}/session/data/mysql/users/${username}/permissions?token=${token}`,
            [
              {
                op: 'add',
                path: `/connectionPermissions/${connectionId}`,
                value: 'READ'
              }
            ],
            { 
              httpsAgent,
              headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
              },
              timeout: 10000
            }
          );
          
          console.log(`[INFO] Successfully granted permissions using alternative method for user '${username}'`);
          
        } catch (altPermissionError) {
          console.error('Alternative permission method also failed:', {
            message: altPermissionError.message,
            response: altPermissionError.response?.data,
            status: altPermissionError.response?.status
          });
          
          // Log warning but don't fail the entire process
          console.log(`[WARN] Failed to grant permissions, but connection was created. User may need manual permission assignment.`);
        }
      }

      return connectionId;
    } catch (error) {
      console.error('Guacamole create connection error:', {
        message: error.message,
        response: error.response?.data,
        status: error.response?.status,
        config: {
          url: error.config?.url,
          method: error.config?.method,
          data: error.config?.data
        }
      });
      throw new Error(`Failed to create Guacamole connection: ${error.message}`);
    }
  },

  /**
   * Constructs the full Guacamole client URL for a given connection ID.
   * @param {string} connectionId The ID of the Guacamole connection.
   * @returns {string} The full URL to access the VM via Guacamole.
   */
  getConnectionUrl(connectionId) {
    // Derives the base URL for Guacamole client from environment variables
    const base = process.env.GUACAMOLE_BASE_URL || process.env.GUACAMOLE_API_URL?.replace(/\/api.*/, '') || 'http://localhost:8080';
    return `${base}/#/client/${connectionId}`;
  },

  /**
   * Gets an authenticated Guacamole URL for a specific user and connection.
   * @param {string} username The username to authenticate.
   * @param {string} connectionId The ID of the Guacamole connection.
   * @returns {Promise<string>} The authenticated URL to access the VM via Guacamole.
   */
  async getAuthenticatedUrl(username, connectionId) {
    try {
      const token = await this.getToken();
      const base = process.env.GUACAMOLE_BASE_URL || process.env.GUACAMOLE_API_URL?.replace(/\/api.*/, '') || 'http://localhost:8080';
      
      // Create a user token for direct access
      try {
        const userToken = await axios.post(
          `${process.env.GUACAMOLE_API_URL}/tokens`,
          {
            username: username,
            password: 'sac@1234'
          },
          {
            httpsAgent,
            headers: {
              'Content-Type': 'application/x-www-form-urlencoded'
            },
            timeout: 10000
          }
        );
        
        if (userToken.data && userToken.data.authToken) {
          return `${base}/#/client/${connectionId}?token=${userToken.data.authToken}`;
        }
      } catch (userTokenError) {
        console.error('Failed to get user token:', userTokenError.message);
      }
      
      // Fallback to regular URL
      return `${base}/#/client/${connectionId}`;
    } catch (error) {
      console.error('Error creating authenticated URL:', error.message);
      return this.getConnectionUrl(connectionId);
    }
  },

  /**
   * Deletes a Guacamole user and its associated connection.
   * @param {string} username The username to delete.
   * @param {string} connectionId The ID of the connection to delete.
   * @returns {Promise<void>}
   * @throws {Error} If deletion fails.
   */
  async deleteGuacamoleUserAndConnection(username, connectionId) {
    try {
      const token = await this.getToken();
      
      console.log(`[INFO] Deleting Guacamole connection with ID: ${connectionId}`);
      await axios.delete(
        `${process.env.GUACAMOLE_API_URL}/session/data/mysql/connections/${connectionId}?token=${token}`,
        {
          httpsAgent,
          headers: {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
          },
          timeout: 10000
        }
      );
      
      console.log(`[INFO] Deleting Guacamole user '${username}'`);
      await axios.delete(
        `${process.env.GUACAMOLE_API_URL}/session/data/mysql/users/${username}?token=${token}`,
        {
          httpsAgent,
          headers: {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
          },
          timeout: 10000
        }
      );
      console.log(`[INFO] Successfully deleted Guacamole user '${username}' and connection with ID ${connectionId}`);
    } catch (error) {
      console.error(`Error deleting Guacamole user or connection:`, {
        message: error.message,
        response: error.response?.data,
        status: error.response?.status
      });
      throw new Error(`Failed to delete Guacamole user or connection: ${error.message}`);
    }
  }
};

// --- Helper Functions ---

/**
 * Checks the current power status of a Proxmox VM.
 * @param {string} vmId The ID of the VM to check.
 * @returns {Promise<string>} 'running', 'stopped', or 'error'.
 */
async function checkVmStatus(vmId) {
  try {
    const nodeName = process.env.PROXMOX_NODE || 'satyam';
    const response = await proxmoxApi.get(`/nodes/${nodeName}/qemu/${vmId}/status/current`);

    if (!response.data || !response.data.data) { // Proxmox often wraps data in a 'data' field
      console.error('Empty or invalid response from Proxmox API for VM status:', response.data);
      return 'error';
    }

    const status = response.data.data.status || response.data.data.qmpstatus;
    if (status === 'running') {
      return 'running';
    }
    return 'stopped';
  } catch (error) {
    console.error(`Status check error for VM ${vmId}:`, error.response?.data || error.message);
    return 'error';
  }
}

/**
 * Retrieves the IPv4 address of a Proxmox VM using the QEMU agent.
 * @param {string} vmId The ID of the VM.
 * @returns {Promise<string|null>} The IPv4 address or null if not found.
 */
async function getVmIp(vmId) {
  try {
    const nodeName = process.env.PROXMOX_NODE || 'satyam';
    // Requires QEMU guest agent to be installed and running on the VM
    const response = await proxmoxApi.get(`/nodes/${nodeName}/qemu/${vmId}/agent/network-get-interfaces`);

    if (!response.data || !response.data.data || !response.data.data.result) {
      throw new Error('No network interfaces data returned from QEMU agent');
    }

    const interfaces = response.data.data.result;
    for (const iface of interfaces) {
      // Exclude loopback interface and check for IPv4 addresses
      if (iface.name !== 'lo' && iface['ip-addresses']) {
        for (const addr of iface['ip-addresses']) {
          if (addr['ip-address-type'] === 'ipv4') {
            return addr['ip-address'];
          }
        }
      }
    }
    return null; // No IPv4 found
  } catch (error) {
    console.error(`IP detection error for VM ${vmId}:`, error.response?.data || error.message);
    return null;
  }
}

/**
 * Starts a Proxmox VM.
 * @param {string} vmId The ID of the VM to start.
 * @returns {Promise<object>} Proxmox API response for the start command.
 * @throws {Error} If the VM cannot be started.
 */
async function startVm(vmId) {
  const nodeName = process.env.PROXMOX_NODE || 'satyam';
  try {
    // First, check if the VM exists and its current status
    const exists = await proxmoxApi.get(`/nodes/${nodeName}/qemu/${vmId}/status/current`);
    if (!exists.data || !exists.data.data) {
      throw new Error('VM not found or invalid response from Proxmox when checking existence.');
    }

    const currentStatus = exists.data.data.status || exists.data.data.qmpstatus;
    console.log(`[DEBUG] Current VM ${vmId} status before start command: ${currentStatus}`);

    // If VM is already running, no need to send start command
    if (currentStatus === 'running') {
      console.log(`[INFO] VM ${vmId} is already running.`);
      return { success: true, message: 'VM already running' };
    }

    // Check if VM is locked (e.g., due to a previous task)
    if (exists.data.data.lock) {
      console.log(`[WARN] VM ${vmId} is locked: ${exists.data.data.lock}. This might cause issues.`);
      // Consider adding a retry mechanism here for locked VMs
    }

    // Send the start command to Proxmox
    console.log(`[INFO] Sending start command to VM ${vmId}...`);
    const response = await proxmoxApi.post(
      `/nodes/${nodeName}/qemu/${vmId}/status/start`,
      {}, // Empty body for POST request
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded' // Required by Proxmox for some POST actions
        },
        timeout: 30000 // Extended timeout for starting VM
      }
    );

    console.log(`[DEBUG] Proxmox start command response for VM ${vmId}:`, response.data);
    return response.data;
  } catch (error) {
    console.error(`Error starting VM ${vmId}:`, error.response?.data || error.message);
    if (error.response?.status === 500 && error.response?.data?.errors) {
      console.error(`Proxmox detailed error:`, error.response.data.errors);
    }
    throw error;
  }
}

/**
 * Finds an available (stopped) VM within a predefined range (101-109) on Proxmox.
 * @returns {Promise<string|null>} The ID of an available VM or null if none found.
 */
async function getAvailableVmId() {
  const nodeName = process.env.PROXMOX_NODE || 'satyam';
  console.log(`[INFO] Searching for available VMs on Proxmox node: ${nodeName}`);

  try {
    // Fetch a list of all VMs on the specified Proxmox node
    const response = await proxmoxApi.get(`/nodes/${nodeName}/qemu`, {
      timeout: 15000,
      headers: { 'Accept': 'application/json' }
    });

    if (!response.data || !response.data.data) {
      console.error('[ERROR] Invalid response format from Proxmox API when listing VMs:', response.data);
      return null;
    }

    const vmList = response.data.data;
    console.log(`[DEBUG] Found ${vmList.length} VMs in Proxmox.`);

    // Filter VMs to include only those in the range 101-109 and exclude templates
    const targetVms = vmList.filter(vm => {
      const vmId = parseInt(vm.vmid);
      return vmId >= 101 && vmId <= 109 && vm.template !== 1; // vm.template = 1 indicates a template
    });

    console.log(`[DEBUG] Filtered VMs in target range (101-109, non-templates): ${targetVms.map(v => v.vmid).join(', ')}`);

    if (targetVms.length === 0) {
      console.log('[WARN] No VMs found in the configured target range (101-109).');
      return null;
    }

    // Check the detailed status of each target VM to find a 'stopped' one
    for (const vm of targetVms) {
      const vmId = vm.vmid;
      try {
        console.log(`[DEBUG] Checking detailed status of VM ${vmId}...`);
        const statusResponse = await proxmoxApi.get(
          `/nodes/${nodeName}/qemu/${vmId}/status/current`,
          {
            timeout: 10000,
            headers: { 'Accept': 'application/json' }
          }
        );

        const vmData = statusResponse.data?.data || statusResponse.data;
        console.log(`[DEBUG] Parsed status for VM ${vmId}:`, vmData?.status || vmData?.qmpstatus || 'unknown');

        // Return the VM ID if it's in a stopped state
        if (vmData && (vmData.status === 'stopped' || vmData.qmpstatus === 'stopped')) {
          console.log(`[INFO] Found available (stopped) VM: ${vmId}`);
          return vmId.toString(); // Ensure consistent string return type
        }
      } catch (error) {
        console.error(`[ERROR] Error checking status for VM ${vmId}. It might be offline or inaccessible:`, error.message);
        // Continue to the next VM if there's an error checking status
      }
    }

    console.log('[INFO] No stopped VMs found in the target range that are currently available.');
    return null;
  } catch (error) {
    console.error('Error fetching VM list from Proxmox:', error.response?.data || error.message);
    return null;
  }
}

// --- Controller Methods ---

/**
 * Handles the request to start a lab VM for a user.
 * It finds an available VM, starts it, gets its IP, creates a Guacamole connection,
 * and updates the database.
 * @param {object} req The Express request object.
 * @param {object} res The Express response object.
 */
exports.startLabVM = async (req, res) => {
  const { labId } = req.body;
  
  // Validate user object
  if (!req.user || !req.user.id) {
    return res.status(401).json({ message: 'User not authenticated' });
  }
  
  const userId = req.user.id;
  // Get username from user object or use a default pattern if not available
  const username = req.user.username || `user_${userId}`;
  
  if (!username) {
    return res.status(400).json({ message: 'Username is required' });
  }
  let vmRecord; // To store the database VM record for potential cleanup

  if (!labId) {
    return res.status(400).json({ message: 'labId is required to start a lab VM.' });
  }

  try {
    // First, check if this is a web lab - if so, redirect to web lab interface
    const { Lab } = require('../models');
    const lab = await Lab.findByPk(labId);
    
    if (!lab) {
      return res.status(404).json({ message: 'Lab not found' });
    }
    
    if (lab.labType === 'web') {
      // For web labs, no VM is needed - redirect to web lab interface
      console.log(`[INFO] Lab ${labId} is a web lab, redirecting to web interface`);
      return res.json({
        message: 'Web lab ready - no VM required',
        labType: 'web',
        redirectTo: `/labs/web/${labId}`,
        status: 'ready'
      });
    }
    // 1. Verify Proxmox API connection at the start
    try {
      const test = await proxmoxApi.get('/version');
      console.log('Proxmox API connection successful. Version:', test.data?.version || 'N/A');
    } catch (error) {
      console.error('Proxmox API connection failed:', error.response?.data || error.message);
      return res.status(500).json({
        message: 'Failed to connect to Proxmox. Please check API configuration.',
        error: error.message
      });
    }

    // 2. Check for an existing active VM for this user and lab in the database
    const existingVm = await VM.findOne({
      where: {
        userId,
        labId,
        status: { [Op.in]: ['creating', 'running'] }, // Consider VMs in 'creating' state as active too
      },
    });

    if (existingVm && existingVm.guacamoleConnectionId) {
      console.log(`[INFO] User ${userId} already has an active VM (${existingVm.vmId}) for lab ${labId}.`);
      return res.json({
        message: 'VM already active for this lab.',
        vmId: existingVm.vmId,
        status: existingVm.status,
        guacamoleUrl: guacamoleApi.getConnectionUrl(existingVm.guacamoleConnectionId),
      });
    }

    // 3. Find an available, stopped VM from the Proxmox pool (101-109)
    console.log('[INFO] Searching for an available stopped VM from Proxmox...');
    let availableVmId = await getAvailableVmId();

    // If Proxmox doesn't report an available VM, check the database for any 'stopped' VMs that might be freed up
    // This adds a layer of robustness if Proxmox list is slow to update or we're tracking more closely in DB
    if (!availableVmId) {
      const dbStoppedVm = await VM.findOne({
        where: { status: 'stopped', userId: null, labId: null } // Find a truly unassigned, stopped VM
      });
      if (dbStoppedVm) {
        availableVmId = parseInt(dbStoppedVm.vmId);
        console.log(`[INFO] Found available (stopped and unassigned) VM in database: ${availableVmId}`);
      }
    }

    if (!availableVmId) {
      console.warn('[WARN] No available VMs in the pool for provisioning.');
      return res.status(503).json({
        message: 'All lab environments are currently in use or unavailable. Please try again later.',
        error: 'No available VMs in the pool.'
      });
    }
    console.log(`[INFO] Selected VM ID for provisioning: ${availableVmId}`);

    // 4. Create a preliminary VM record in the database
    // This allows tracking even if subsequent steps fail
    vmRecord = await VM.create({
      userId,
      labId,
      vmId: availableVmId.toString(), // Store as string to match Proxmox vmid
      status: 'creating', // Set initial status to 'creating'
      startTime: new Date(),
    });
    console.log(`[INFO] Created preliminary DB record for VM ${availableVmId}, status: 'creating'.`);

    // 5. Start the Proxmox VM
    console.log(`[INFO] Attempting to start Proxmox VM ${availableVmId}...`);
    await startVm(availableVmId);

    // 6. Wait for the VM to boot up and reach 'running' status
    console.log(`[INFO] Waiting for VM ${availableVmId} to report 'running' status...`);
    let attempts = 0;
    const maxAttempts = 60; // 5 minutes (60 attempts * 5 seconds wait = 300 seconds)
    const delay = 5000; // 5 seconds
    let vmStatus = '';
    while (attempts < maxAttempts) {
      await new Promise(resolve => setTimeout(resolve, delay)); // Wait before checking
      vmStatus = await checkVmStatus(availableVmId);
      console.log(`[INFO] VM ${availableVmId} status check ${attempts + 1}/${maxAttempts}: ${vmStatus}`);

      if (vmStatus === 'running') break; // VM is running, proceed
      if (vmStatus === 'error') {
        // If status check itself returns error, try to get more details
        try {
          const detailedStatus = await proxmoxApi.get(
            `/nodes/${process.env.PROXMOX_NODE || 'satyam'}/qemu/${availableVmId}/status/current`,
            { timeout: 10000 }
          );
          console.error('Detailed VM status during boot failure:', detailedStatus.data?.data || detailedStatus.data);

          // If VM is actually running but our `checkVmStatus` failed, break
          if (detailedStatus.data?.data &&
            (detailedStatus.data.data.status === 'running' || detailedStatus.data.data.qmpstatus === 'running')) {
            vmStatus = 'running';
            console.log(`[INFO] VM ${availableVmId} is actually running despite previous 'error' status. Continuing.`);
            break;
          }
        } catch (detailError) {
          console.error(`[ERROR] Could not get detailed VM status for ${availableVmId}:`, detailError.message);
        }
      }
      attempts++;
    }

    if (vmStatus !== 'running') {
      const finalProxmoxStatus = await proxmoxApi.get(
        `/nodes/${process.env.PROXMOX_NODE || 'satyam'}/qemu/${availableVmId}/status/current`,
        { timeout: 10000 }
      ).catch(err => {
        console.error(`Failed to get final Proxmox status for ${availableVmId}:`, err.message);
        return { data: { data: { status: 'unavailable' } } }; // Default if final check fails
      });
      throw new Error(`VM ${availableVmId} failed to reach 'running' status within the allotted time. Final Proxmox status: ${finalProxmoxStatus.data?.data?.status || 'unknown'}.`);
    }

    // 7. Wait for VM to fully boot and get its IP address
    console.log(`[INFO] Waiting for VM ${availableVmId} to fully boot and get IP address...`);
    let ipAddress = null;
    const maxIpRetries = 12; // Try for up to 60 seconds (12 * 5s)
    let ipRetryCount = 0;
    
    while (ipRetryCount < maxIpRetries && !ipAddress) {
      ipRetryCount++;
      console.log(`[INFO] Attempt ${ipRetryCount}/${maxIpRetries} to get IP for VM ${availableVmId}...`);
      
      // Add increasing delay between retries (first attempt is immediate)
      if (ipRetryCount > 1) {
        await new Promise(resolve => setTimeout(resolve, 5000)); // 5 second delay
      }
      
      // Try to get the IP
      ipAddress = await getVmIp(availableVmId);
      
      if (ipAddress) {
        console.log(`[INFO] Successfully retrieved IP for VM ${availableVmId}: ${ipAddress}`);
        
        // Verify the IP is reachable (optional but recommended)
        try {
          // Simple TCP connection test to common ports (e.g., SSH)
          await new Promise((resolve, reject) => {
            const net = require('net');
            const socket = net.createConnection(22, ipAddress, () => {
              socket.end();
              resolve();
            });
            
            socket.setTimeout(3000);
            socket.on('timeout', () => {
              socket.destroy();
              reject(new Error('Connection timeout'));
            });
            
            socket.on('error', (err) => {
              reject(err);
            });
          });
          
          console.log(`[INFO] Successfully verified VM ${availableVmId} is reachable at ${ipAddress}`);
          break; // Exit the retry loop if IP is reachable
          
        } catch (reachabilityError) {
          console.log(`[WARN] VM ${availableVmId} at ${ipAddress} is not yet reachable: ${reachabilityError.message}`);
          ipAddress = null; // Reset IP to force retry
        }
      } else {
        console.log(`[INFO] IP address not yet available for VM ${availableVmId}, waiting...`);
      }
    }
    
    if (!ipAddress) {
      throw new Error(`Failed to retrieve a reachable IP address for VM ${availableVmId} after ${maxIpRetries} attempts. The VM may need more time to boot or the QEMU guest agent may not be running.`);
    }
    
    console.log(`[INFO] VM ${availableVmId} is fully booted and reachable at IP: ${ipAddress}`);

    // 8. Create or ensure Guacamole User exists
    console.log(`[INFO] Ensuring Guacamole user '${username}' exists.`);
    await guacamoleApi.createUser(username);

    // 9. Create Guacamole Connection for the VM
    const connectionName = `Lab-${labId}-VM-${availableVmId}`; // A more descriptive connection name
    console.log(`[INFO] Creating Guacamole connection '${connectionName}' for VM ${availableVmId} (IP: ${ipAddress}).`);
    const connectionId = await guacamoleApi.createConnection(username, connectionName, ipAddress);

    // 10. Update the VM record in the database with final details
    vmRecord.status = 'running';
    vmRecord.ipAddress = ipAddress;
    vmRecord.guacamoleConnectionId = connectionId;
    vmRecord.endTime = null; // Clear endTime if re-starting
    await vmRecord.save();
    console.log(`[INFO] VM ${availableVmId} record updated in DB with 'running' status and Guacamole details.`);

    // 11. Schedule automatic stop based on lab duration
    try {
      const userContext = {
        id: userId,
        username: username,
        email: req.user.email || `${username}@local.com`
      };
      
      const autoStopScheduled = await labAutoStopService.scheduleLabAutoStop(
        vmRecord.id,       // VM database ID
        labId,             // Lab ID
        lab.duration,      // Duration in minutes from lab configuration
        userContext        // User context
      );
      
      if (autoStopScheduled) {
        console.log(`[INFO] Auto-stop scheduled for VM ${vmRecord.id} after ${lab.duration} minutes`);
      } else {
        console.warn(`[WARN] Failed to schedule auto-stop for VM ${vmRecord.id}`);
      }
    } catch (autoStopError) {
      // Don't fail the entire VM start process if auto-stop scheduling fails
      console.error(`[ERROR] Failed to schedule auto-stop for VM ${vmRecord.id}:`, autoStopError.message);
      labAutoStopService.logAutoStop('ERROR', 'Auto-stop scheduling failed during VM start', {
        vmDatabaseId: vmRecord.id,
        labId,
        error: autoStopError.message
      });
    }

    // 12. Return the Guacamole URL to the client
    const guacamoleUrl = guacamoleApi.getConnectionUrl(connectionId);
    console.log(`[INFO] Successfully provisioned and started VM ${availableVmId} for user ${userId}. Guacamole URL: ${guacamoleUrl}`);

    res.json({
      message: 'Lab environment started successfully.',
      vmId: availableVmId,
      status: 'running',
      ipAddress: ipAddress,
      guacamoleUrl,
    });

  } catch (error) {
    console.error('[ERROR] Failed to start lab VM process:', error.message);

    // Rollback/Cleanup logic: Update VM record status to 'failed' and attempt to stop VM
    if (vmRecord) {
      try {
        vmRecord.status = 'failed';
        // Truncate error message if it's too long for the database column
        const maxErrorLength = 255; // Adjust based on your database schema
        vmRecord.errorDetails = error.message ? 
          (error.message.length > maxErrorLength ? 
            error.message.substring(0, maxErrorLength - 3) + '...' : 
            error.message) : 
          'Unknown error';
        vmRecord.endTime = new Date(); // Mark as failed at this time
        await vmRecord.save();
        console.log(`[INFO] VM record ${vmRecord.id} updated with 'failed' status.`);
      } catch (dbErr) {
        console.error('[ERROR] Failed to save VM record with "failed" status:', dbErr.message);
        // Try a more basic update if the detailed one fails
        try {
          await VM.update(
            { status: 'error', endTime: new Date() },
            { where: { id: vmRecord.id } }
          );
          console.log(`[INFO] VM record ${vmRecord.id} updated with basic 'error' status as fallback.`);
        } catch (fallbackErr) {
          console.error('[ERROR] Even fallback VM record update failed:', fallbackErr.message);
        }
      }

      // Attempt to stop the VM in Proxmox if it was assigned and potentially started
      if (vmRecord.vmId) {
        console.log(`[INFO] Attempting to stop VM ${vmRecord.vmId} due to provisioning failure.`);
        try {
          // Send stop command without waiting for confirmation
          await proxmoxApi.post(
            `/nodes/${process.env.PROXMOX_NODE || 'satyam'}/qemu/${vmRecord.vmId}/status/stop`,
            {},
            { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
          );
          console.log(`[INFO] Stop command sent for VM ${vmRecord.vmId}.`);
        } catch (stopError) {
          console.error(`[ERROR] Failed to send stop command for VM ${vmRecord.vmId} during cleanup:`, stopError.response?.data || stopError.message);
        }
      }
    }

    res.status(500).json({
      message: 'Failed to start lab environment. An unexpected error occurred.',
      error: error.message,
      details: error.response?.data || null // Include Proxmox/Guacamole specific error details if available
    });
  }
};

/**
 * Handles the request to stop a running lab VM.
 * @param {object} req The Express request object.
 * @param {object} res The Express response object.
 */
exports.stopLabVM = async (req, res) => {
  try {
    const { vmId: paramVmId } = req.params; // vmId from URL parameter
    const userId = req.user.id;
    const userRole = req.user.role;

    if (!paramVmId) {
      return res.status(400).json({ message: 'VM ID is required to stop a lab environment.' });
    }

    console.log(`[INFO] Stop VM request - User ID: ${userId}, Role: ${userRole}, VM ID: ${paramVmId}`);

    // Try to find VM by multiple methods for better flexibility
    let vm = null;
    let searchMethod = '';

    // Method 1: Search by database record ID (primary method)
    let whereConditions = {
      id: paramVmId,
      status: 'running'
    };

    // If not admin, restrict to user's own VMs
    if (userRole !== 'admin') {
      whereConditions.userId = userId;
    }

    vm = await VM.findOne({
      where: whereConditions,
      include: [
        {
          model: User,
          as: 'user',
          attributes: ['id', 'username', 'email']
        }
      ]
    });

    if (vm) {
      searchMethod = 'database_id';
      console.log(`[DEBUG] Found VM by database ID: ${vm.id} (Proxmox ID: ${vm.vmId})`);
    } else {
      // Method 2: Search by Proxmox VM ID (fallback)
      console.log(`[DEBUG] VM not found by database ID, trying Proxmox VM ID...`);
      
      whereConditions = {
        vmId: paramVmId.toString(),
        status: 'running'
      };

      if (userRole !== 'admin') {
        whereConditions.userId = userId;
      }

      vm = await VM.findOne({
        where: whereConditions,
        include: [
          {
            model: User,
            as: 'user',
            attributes: ['id', 'username', 'email']
          }
        ]
      });

      if (vm) {
        searchMethod = 'proxmox_id';
        console.log(`[DEBUG] Found VM by Proxmox ID: ${vm.id} (Proxmox ID: ${vm.vmId})`);
      }
    }

    if (!vm) {
      console.log(`[DEBUG] VM not found with ID: ${paramVmId}. Checking available VMs...`);
      
      // Provide debug information about available VMs
      const debugWhereConditions = userRole === 'admin' ? {} : { userId: userId };
      
      const availableVMs = await VM.findAll({
        where: debugWhereConditions,
        attributes: ['id', 'vmId', 'status', 'labId', 'userId'],
        include: [
          {
            model: User,
            as: 'user',
            attributes: ['username']
          }
        ],
        limit: 10 // Limit for debugging
      });

      const debugInfo = availableVMs.map(v => ({
        dbId: v.id,
        proxmoxId: v.vmId,
        status: v.status,
        labId: v.labId,
        userId: v.userId,
        username: v.user?.username
      }));

      console.log(`[DEBUG] Available VMs for user:`, debugInfo);

      // Check if VM exists but is not running
      const vmAnyStatus = await VM.findOne({
        where: {
          [Op.or]: [
            { id: paramVmId },
            { vmId: paramVmId.toString() }
          ],
          ...(userRole !== 'admin' && { userId: userId })
        }
      });

      if (vmAnyStatus) {
        return res.status(400).json({
          message: `VM found but is not running. Current status: ${vmAnyStatus.status}`,
          vmId: vmAnyStatus.id,
          proxmoxVmId: vmAnyStatus.vmId,
          status: vmAnyStatus.status,
          availableRunningVMs: debugInfo.filter(v => v.status === 'running')
        });
      }

      const message = userRole === 'admin'
        ? `Running VM not found with ID: ${paramVmId}`
        : `Running VM not found with ID: ${paramVmId} or not associated with your account.`;
      
      return res.status(404).json({
        message,
        searchedId: paramVmId,
        userRole,
        userId: userRole === 'admin' ? 'any' : userId,
        availableRunningVMs: debugInfo.filter(v => v.status === 'running'),
        hint: 'Use the dbId from availableRunningVMs for stop requests'
      });
    }

    console.log(`[INFO] ${userRole === 'admin' ? 'Admin' : 'User'} stopping VM ${vm.id} (Proxmox ID: ${vm.vmId}) owned by user ${vm.userId} (found by: ${searchMethod})`);

    const nodeName = process.env.PROXMOX_NODE || 'satyam';
    const proxmoxVmId = vm.vmId; // The actual VM ID on Proxmox

    console.log(`[INFO] Attempting to stop Proxmox VM ${proxmoxVmId} for user ${userId}.`);

    // Clean up Guacamole user and connection before stopping VM
    if (vm.guacamoleConnectionId) {
      try {
        // Use the VM owner's user ID for Guacamole cleanup, not the current user's ID
        const vmOwnerUserId = vm.userId; // The actual owner of the VM
        const vmOwnerUsername = vm.user.username || `user_${vmOwnerUserId}`; // Use actual username or fallback pattern

        console.log(`[INFO] ${userRole === 'admin' ? 'Admin' : 'User'} cleaning up Guacamole user '${vmOwnerUsername}' (owner: ${vmOwnerUserId}) and connection '${vm.guacamoleConnectionId}'`);
        await guacamoleApi.deleteGuacamoleUserAndConnection(vmOwnerUsername, vm.guacamoleConnectionId);
        console.log(`[INFO] Successfully cleaned up Guacamole resources for VM owner ${vmOwnerUserId}`);
      } catch (guacCleanupError) {
        // Don't fail the entire stop process if Guacamole cleanup fails
        console.error(`[WARN] Failed to cleanup Guacamole resources:`, guacCleanupError.message);
        console.log(`[INFO] Continuing with VM stop despite Guacamole cleanup failure`);
      }
    }

    // Send stop command to Proxmox
    try {
      await proxmoxApi.post(
        `/nodes/${nodeName}/qemu/${proxmoxVmId}/status/stop`,
        {},
        {
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
          },
          timeout: 20000 // 20-second timeout for stop command
        }
      );
      console.log(`[INFO] Proxmox VM ${proxmoxVmId} stop command sent successfully.`);
    } catch (proxmoxError) {
      console.error(`[ERROR] Failed to send stop command to Proxmox VM ${proxmoxVmId}:`, proxmoxError.response?.data || proxmoxError.message);
      
      // Even if Proxmox stop fails, we should update the database to reflect the attempt
      // This prevents the VM from being stuck in 'running' state
      vm.status = 'error';
      vm.endTime = new Date();
      vm.errorDetails = `Stop command failed: ${proxmoxError.message}`;
      await vm.save();
      
      return res.status(500).json({
        message: 'Failed to stop lab environment in Proxmox.',
        error: proxmoxError.message,
        vmId: vm.id,
        proxmoxVmId: vm.vmId,
        hint: 'VM status updated to error. You may need to manually stop it in Proxmox.'
      });
    }

    // Cancel any active auto-stop timer for this VM
    try {
      const cancelResult = labAutoStopService.cancelLabAutoStop(vm.id);
      if (cancelResult) {
        console.log(`[INFO] Cancelled auto-stop timer for VM ${vm.id}`);
      }
    } catch (cancelError) {
      console.error(`[WARN] Failed to cancel auto-stop timer for VM ${vm.id}:`, cancelError.message);
    }

    // Update the VM record in the database
    vm.status = 'stopped';
    vm.endTime = new Date();
    // Clear Guacamole connection ID since resources have been cleaned up
    vm.guacamoleConnectionId = null;
    await vm.save();
    console.log(`[INFO] VM record ${vm.id} updated to 'stopped' in database.`);

    res.json({
      message: 'Lab environment stopped successfully.',
      vmId: vm.id,
      proxmoxVmId: vm.vmId,
      status: vm.status,
      searchMethod: searchMethod,
      stoppedAt: vm.endTime
    });

  } catch (error) {
    console.error('Stop VM error:', {
      message: error.message,
      stack: error.stack,
      response: error.response?.data,
      status: error.response?.status,
      url: error.config?.url
    });

    res.status(500).json({
      message: 'Failed to stop lab environment. An unexpected error occurred.',
      error: error.message,
      details: error.response?.data || null,
      timestamp: new Date().toISOString()
    });
  }
};

/**
 * Retrieves the status and details of a specific VM for the current user.
 * @param {object} req The Express request object.
 * @param {object} res The Express response object.
 */
exports.getVMStatus = async (req, res) => {
  try {
    const { vmId: paramVmId } = req.params; // This vmId refers to the database record ID
    const userId = req.user.id;

    if (!paramVmId) {
      return res.status(400).json({ message: 'VM ID is required to get status.' });
    }

    // Find the VM record in the database
    const vm = await VM.findOne({
      where: {
        id: paramVmId,
        userId
      },
      include: [
        {
          model: User,
          attributes: ['id', 'username', 'email'] // Include user details
        }
      ]
    });

    if (!vm) {
      return res.status(404).json({ message: 'VM record not found or not associated with your account.' });
    }

    let currentProxmoxStatus = vm.status; // Default to stored status

    // If the VM is theoretically 'running' according to our DB,
    // double-check its real-time status with Proxmox for accuracy.
    if (vm.status === 'running' || vm.status === 'creating') {
      try {
        const nodeName = process.env.PROXMOX_NODE || 'satyam';
        // Use vm.vmId which is the actual Proxmox VM ID
        const statusResponse = await proxmoxApi.get(`/nodes/${nodeName}/qemu/${vm.vmId}/status/current`);

        if (statusResponse.data && statusResponse.data.data) {
          currentProxmoxStatus = statusResponse.data.data.status || statusResponse.data.data.qmpstatus;
          // Update DB if Proxmox status differs
          if (vm.status !== currentProxmoxStatus) {
            console.log(`[INFO] Updating DB status for VM ${vm.id} from '${vm.status}' to '${currentProxmoxStatus}'.`);
            vm.status = currentProxmoxStatus;
            await vm.save();
          }
        } else {
          console.warn(`[WARN] No valid status data from Proxmox for VM ${vm.vmId}.`);
        }
      } catch (error) {
        console.error(`Error getting real-time Proxmox status for VM ${vm.vmId}:`, error.response?.data || error.message);
        // If Proxmox check fails, assume it might be off or errored, but don't fail the entire request
        currentProxmoxStatus = 'unknown_proxmox_error';
      }
    }

    // Construct the response object
    res.json({
      id: vm.id, // Database record ID
      vmId: vm.vmId, // Proxmox VM ID
      status: currentProxmoxStatus, // Real-time or stored status
      ipAddress: vm.ipAddress,
      startTime: vm.startTime,
      endTime: vm.endTime,
      labId: vm.labId,
      errorDetails: vm.errorDetails,
      guacamoleUrl: vm.guacamoleConnectionId ?
        guacamoleApi.getConnectionUrl(vm.guacamoleConnectionId) : null,
      user: vm.User // Include associated user details
    });
  } catch (error) {
    console.error('Get VM status error:', error.response?.data || error.message);
    res.status(500).json({
      message: 'Failed to retrieve VM status. An unexpected error occurred.',
      error: error.message
    });
  }
};

/**
 * Lists all VMs directly from Proxmox, providing their basic details and status.
 * This is primarily for administrative/overview purposes.
 * @param {object} req The Express request object.
 * @param {object} res The Express response object.
 */
exports.listAllVMs = async (req, res) => {
  const nodeName = process.env.PROXMOX_NODE || 'satyam';

  try {
    console.log(`[INFO] Fetching all VMs from Proxmox node: ${nodeName}`);
    const response = await proxmoxApi.get(`/nodes/${nodeName}/qemu`, {
      timeout: 15000,
      headers: { 'Accept': 'application/json' }
    });

    if (!response.data || !response.data.data) {
      return res.status(500).json({
        message: 'Failed to fetch VMs from Proxmox.',
        error: 'Invalid response format from Proxmox API.'
      });
    }

    const vms = [];
    const vmList = response.data.data || [];

    // Iterate through each VM from Proxmox and get its detailed status
    for (const vm of vmList) {
      try {
        const statusResponse = await proxmoxApi.get(
          `/nodes/${nodeName}/qemu/${vm.vmid}/status/current`,
          {
            timeout: 10000,
            headers: { 'Accept': 'application/json' }
          }
        );

        const vmData = statusResponse.data?.data || statusResponse.data; // Handle different wrapper levels

        vms.push({
          vmid: vm.vmid,
          name: vm.name || `VM-${vm.vmid}`, // Use vm.name if available, otherwise a generic name
          status: vmData?.status || 'unknown',
          qmpstatus: vmData?.qmpstatus || 'unknown',
          cpus: vmData?.cpus || 0,
          maxmem: vmData?.maxmem || 0, // Max memory in bytes
          mem: vmData?.mem || 0,     // Current memory usage in bytes
          isTemplate: vm.template === 1,
          node: nodeName
        });
      } catch (error) {
        console.error(`[ERROR] Error getting detailed status for Proxmox VM ${vm.vmid}:`, error.message);
        vms.push({
          vmid: vm.vmid,
          name: vm.name || `VM-${vm.vmid}`,
          status: 'error_fetching_status',
          error: error.message,
          isTemplate: vm.template === 1,
          node: nodeName
        });
      }
    }

    res.json({
      node: nodeName,
      count: vms.length,
      vms: vms
    });

  } catch (error) {
    console.error('[ERROR] Error listing all VMs from Proxmox:', error.response?.data || error.message);
    res.status(500).json({
      message: 'Failed to list VMs from Proxmox. Please check Proxmox connectivity and API token.',
      error: error.message,
      details: error.response?.data || null
    });
  }
};

/**
 * Gets the status of a Proxmox VM by its Proxmox VM ID for polling during startup
 * @param {object} req The Express request object.
 * @param {object} res The Express response object.
 */
exports.getProxmoxVMStatus = async (req, res) => {
  try {
    const { proxmoxVmId } = req.params;
    const userId = req.user.id;

    if (!proxmoxVmId) {
      return res.status(400).json({ message: 'Proxmox VM ID is required.' });
    }

    console.log(`[INFO] Getting status for Proxmox VM ${proxmoxVmId} for user ${userId}`);

    // First, find the VM record in database to ensure user has access
    const vmRecord = await VM.findOne({
      where: {
        vmId: proxmoxVmId.toString(),
        userId: userId
      }
    });

    if (!vmRecord) {
      return res.status(404).json({ 
        message: 'VM not found or not associated with your account.',
        status: 'not_found'
      });
    }

    // Get real-time status from Proxmox
    const nodeName = process.env.PROXMOX_NODE || 'satyam';
    let vmStatus = 'unknown';
    let ipAddress = null;
    let errorDetails = null;

    try {
      // Check VM status
      const statusResponse = await proxmoxApi.get(`/nodes/${nodeName}/qemu/${proxmoxVmId}/status/current`);
      
      if (statusResponse.data && statusResponse.data.data) {
        vmStatus = statusResponse.data.data.status || statusResponse.data.data.qmpstatus || 'unknown';
        console.log(`[DEBUG] Proxmox VM ${proxmoxVmId} status: ${vmStatus}`);
      }

      // If VM is running, try to get IP address
      if (vmStatus === 'running') {
        try {
          ipAddress = await getVmIp(proxmoxVmId);
          console.log(`[DEBUG] Proxmox VM ${proxmoxVmId} IP: ${ipAddress || 'not available yet'}`);
        } catch (ipError) {
          console.log(`[DEBUG] Could not get IP for VM ${proxmoxVmId}: ${ipError.message}`);
          // Don't treat IP retrieval failure as an error during startup
        }
      }

    } catch (proxmoxError) {
      console.error(`[ERROR] Failed to get Proxmox status for VM ${proxmoxVmId}:`, proxmoxError.message);
      vmStatus = 'error';
      errorDetails = proxmoxError.message;
    }

    // Update database record if status changed
    if (vmRecord.status !== vmStatus) {
      try {
        vmRecord.status = vmStatus;
        if (ipAddress && !vmRecord.ipAddress) {
          vmRecord.ipAddress = ipAddress;
        }
        await vmRecord.save();
        console.log(`[INFO] Updated VM ${vmRecord.id} status to '${vmStatus}' in database`);
      } catch (dbError) {
        console.error(`[ERROR] Failed to update VM status in database:`, dbError.message);
      }
    }

    // Return status information
    res.json({
      vmId: vmRecord.id,
      proxmoxVmId: proxmoxVmId,
      status: vmStatus,
      ipAddress: ipAddress || vmRecord.ipAddress,
      guacamoleUrl: vmRecord.guacamoleConnectionId ? 
        guacamoleApi.getConnectionUrl(vmRecord.guacamoleConnectionId) : null,
      startTime: vmRecord.startTime,
      errorDetails: errorDetails || vmRecord.errorDetails
    });

  } catch (error) {
    console.error('[ERROR] Get Proxmox VM status error:', error.message);
    res.status(500).json({
      message: 'Failed to retrieve VM status.',
      error: error.message,
      status: 'error'
    });
  }
};

/**
 * Retrieves a list of all active (non-stopped, non-error) VMs from the database,
 * including associated user information.
 * @param {object} req The Express request object.
 * @param {object} res The Express response object.
 */
exports.getAllActiveVMs = async (req, res) => {
  try {
    const activeVMs = await VM.findAll({
      where: {
        status: {
          [Op.notIn]: ['stopped', 'error', 'failed'] // Exclude stopped, error, and failed VMs
        }
      },
      include: [
        {
          model: User,
          as: 'user', // Alias for the association
          attributes: ['id', 'username', 'email']
        }
      ],
      order: [['startTime', 'DESC']] // Order by start time, newest first
    });

    res.json({
      count: activeVMs.length,
      vms: activeVMs.map(vm => ({
        id: vm.id, // Database record ID
        vmId: vm.vmId, // Proxmox VM ID
        labId: vm.labId,
        status: vm.status,
        ipAddress: vm.ipAddress,
        startTime: vm.startTime,
        endTime: vm.endTime,
        errorDetails: vm.errorDetails,
        user: {
          id: vm.user.id,
          username: vm.user.username,
          email: vm.user.email
        },
        guacamoleUrl: vm.guacamoleConnectionId ?
          guacamoleApi.getConnectionUrl(vm.guacamoleConnectionId) : null
      }))
    });
  } catch (error) {
    console.error('Get all active VMs from DB error:', error.message);
    res.status(500).json({
      message: 'Failed to retrieve active VM list from the database.',
      error: error.message
    });
  }
};/**
 * Retrieves VM information by lab ID for the current user.
 * @param {object} req The Express request object.
 * @param {object} res The Express response object.
 */
exports.getVMByLabId = async (req, res) => {
  try {
    const { labId } = req.params;
    const userId = req.user.id;

    if (!labId) {
      return res.status(400).json({ message: 'Lab ID is required.' });
    }

    console.log(`[INFO] Retrieving VM for lab ${labId} and user ${userId}`);

    // First try to find a running VM, then fallback to the most recent VM
    let vmRecord = await VM.findOne({
      where: {
        labId: labId,
        userId: userId,
        status: 'running'
      },
      order: [['createdAt', 'DESC']]
    });
    
    // If no running VM found, get the most recent VM regardless of status
    if (!vmRecord) {
      vmRecord = await VM.findOne({
        where: {
          labId: labId,
          userId: userId
        },
        order: [['createdAt', 'DESC']]
      });
    }

    if (!vmRecord) {
      return res.status(404).json({ message: 'No VM found for this lab.', status: 'not_found' });
    }

    // Get simple Guacamole login URL
    let guacamoleUrl = null;
    if (vmRecord.guacamoleConnectionId) {
      guacamoleUrl = 'http://172.16.200.136:8080/guacamole';
    }

    res.json({
      vmId: vmRecord.vmId,
      proxmoxVmId: vmRecord.vmId,
      status: vmRecord.status,
      ipAddress: vmRecord.ipAddress,
      guacamoleUrl: guacamoleUrl
    });
  } catch (error) {
    console.error('Error retrieving VM by lab ID:', error.message);
    res.status(500).json({ message: 'Failed to retrieve VM.', error: error.message });
  }
};

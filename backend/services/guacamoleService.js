const axios = require('axios');
const { User, Team } = require('../models');

class GuacamoleService {
  constructor() {
    this.baseUrl = 'http://172.16.200.136:8080/guacamole';
    this.apiUrl = 'http://172.16.200.136:8080/guacamole/api';
    this.adminCredentials = {
      username: 'guacadmin',
      password: 'guacadmin'
    };
    this.authToken = null;
    this.defaultPassword = 'sac@1234';
  }

  /**
   * Authenticate with Guacamole API
   */
  async authenticate() {
    try {
      const response = await axios.post(`${this.apiUrl}/tokens`, {
        username: this.adminCredentials.username,
        password: this.adminCredentials.password
      });

      this.authToken = response.data.authToken;
      console.log('✅ Authenticated with Guacamole API');
      return true;
    } catch (error) {
      console.error('❌ Failed to authenticate with Guacamole:', error.message);
      return false;
    }
  }

  /**
   * Create a new user in Guacamole
   */
  async createUser(username, fullName, email) {
    try {
      if (!this.authToken) {
        const authenticated = await this.authenticate();
        if (!authenticated) {
          throw new Error('Failed to authenticate with Guacamole');
        }
      }

      // Create user
      const userData = {
        username: username,
        password: this.defaultPassword,
        attributes: {
          fullName: fullName,
          emailAddress: email,
          organization: 'CyberRange',
          role: 'USER'
        }
      };

      const response = await axios.post(`${this.apiUrl}/session/data/mysql/users`, userData, {
        headers: {
          'Authorization': `Bearer ${this.authToken}`,
          'Content-Type': 'application/json'
        }
      });

      console.log(`✅ Created Guacamole user: ${username}`);
      return { success: true, userId: response.data.identifier };
    } catch (error) {
      if (error.response && error.response.status === 409) {
        console.log(`ℹ️  Guacamole user ${username} already exists`);
        return { success: true, exists: true };
      }
      console.error(`❌ Failed to create Guacamole user ${username}:`, error.message);
      return { success: false, error: error.message };
    }
  }

  /**
   * Assign connection to user
   */
  async assignConnectionToUser(username, connectionName = 'Windows7-Target') {
    try {
      if (!this.authToken) {
        const authenticated = await this.authenticate();
        if (!authenticated) {
          throw new Error('Failed to authenticate with Guacamole');
        }
      }

      // Get connection ID
      const connectionsResponse = await axios.get(`${this.apiUrl}/session/data/mysql/connections`, {
        headers: {
          'Authorization': `Bearer ${this.authToken}`
        }
      });

      const connection = connectionsResponse.data.find(conn => conn.name === connectionName);
      if (!connection) {
        console.log(`⚠️  Connection ${connectionName} not found in Guacamole`);
        return { success: false, error: 'Connection not found' };
      }

      // Get user ID
      const usersResponse = await axios.get(`${this.apiUrl}/session/data/mysql/users`, {
        headers: {
          'Authorization': `Bearer ${this.authToken}`
        }
      });

      const user = usersResponse.data.find(u => u.username === username);
      if (!user) {
        console.log(`⚠️  User ${username} not found in Guacamole`);
        return { success: false, error: 'User not found' };
      }

      // Assign connection to user
      const assignmentData = {
        op: 'add',
        path: '/connectionPermissions',
        value: connection.identifier
      };

      await axios.patch(`${this.apiUrl}/session/data/mysql/users/${user.identifier}/permissions`, [assignmentData], {
        headers: {
          'Authorization': `Bearer ${this.authToken}`,
          'Content-Type': 'application/json'
        }
      });

      console.log(`✅ Assigned connection ${connectionName} to user ${username}`);
      return { success: true };
    } catch (error) {
      console.error(`❌ Failed to assign connection to user ${username}:`, error.message);
      return { success: false, error: error.message };
    }
  }

  /**
   * Create user and assign connection
   */
  async setupUserAccess(user) {
    try {
      console.log(`Setting up Guacamole access for user: ${user.username}`);

      // Create user in Guacamole
      const createResult = await this.createUser(
        user.username,
        user.username,
        user.email
      );

      if (!createResult.success) {
        return createResult;
      }

      // Assign connection to user
      const assignResult = await this.assignConnectionToUser(user.username);
      if (!assignResult.success) {
        return assignResult;
      }

      return {
        success: true,
        message: `Guacamole access configured for ${user.username}`,
        credentials: {
          username: user.username,
          password: this.defaultPassword,
          url: this.baseUrl
        }
      };
    } catch (error) {
      console.error(`❌ Failed to setup Guacamole access for ${user.username}:`, error.message);
      return { success: false, error: error.message };
    }
  }

  /**
   * Setup team access (create users for all team members)
   */
  async setupTeamAccess(teamId) {
    try {
      const team = await Team.findByPk(teamId, {
        include: [{ model: User, as: 'members' }]
      });

      if (!team) {
        return { success: false, error: 'Team not found' };
      }

      console.log(`Setting up Guacamole access for team: ${team.name}`);

      const results = [];
      for (const member of team.members) {
        const result = await this.setupUserAccess(member);
        results.push({
          username: member.username,
          success: result.success,
          message: result.message || result.error
        });
      }

      return {
        success: true,
        teamName: team.name,
        results: results
      };
    } catch (error) {
      console.error(`❌ Failed to setup team access:`, error.message);
      return { success: false, error: error.message };
    }
  }

  /**
   * Get user connection info
   */
  async getUserConnectionInfo(username) {
    try {
      if (!this.authToken) {
        const authenticated = await this.authenticate();
        if (!authenticated) {
          throw new Error('Failed to authenticate with Guacamole');
        }
      }

      const response = await axios.get(`${this.apiUrl}/session/data/mysql/users/${username}/permissions`, {
        headers: {
          'Authorization': `Bearer ${this.authToken}`
        }
      });

      return {
        success: true,
        permissions: response.data
      };
    } catch (error) {
      console.error(`❌ Failed to get user connection info for ${username}:`, error.message);
      return { success: false, error: error.message };
    }
  }

  /**
   * Delete user from Guacamole
   */
  async deleteUser(username) {
    try {
      if (!this.authToken) {
        const authenticated = await this.authenticate();
        if (!authenticated) {
          throw new Error('Failed to authenticate with Guacamole');
        }
      }

      // Get user ID
      const usersResponse = await axios.get(`${this.apiUrl}/session/data/mysql/users`, {
        headers: {
          'Authorization': `Bearer ${this.authToken}`
        }
      });

      const user = usersResponse.data.find(u => u.username === username);
      if (!user) {
        console.log(`ℹ️  User ${username} not found in Guacamole`);
        return { success: true, message: 'User not found' };
      }

      // Delete user
      await axios.delete(`${this.apiUrl}/session/data/mysql/users/${user.identifier}`, {
        headers: {
          'Authorization': `Bearer ${this.authToken}`
        }
      });

      console.log(`✅ Deleted Guacamole user: ${username}`);
      return { success: true };
    } catch (error) {
      console.error(`❌ Failed to delete Guacamole user ${username}:`, error.message);
      return { success: false, error: error.message };
    }
  }

  /**
   * Test Guacamole connectivity
   */
  async testConnection() {
    try {
      // Try different API endpoints
      const endpoints = [
        `${this.baseUrl}/api/status`,
        `${this.baseUrl}/api/session/data/mysql/connections`,
        `${this.baseUrl}/api/tokens`
      ];

      for (const endpoint of endpoints) {
        try {
          const response = await axios.get(endpoint, { timeout: 5000 });
          console.log(`✅ Guacamole API accessible at: ${endpoint}`);
          return { success: true, status: response.data, endpoint };
        } catch (endpointError) {
          console.log(`❌ Endpoint ${endpoint} not accessible: ${endpointError.message}`);
        }
      }

      // If no API endpoints work, check if the main page is accessible
      const mainResponse = await axios.get(this.baseUrl, { timeout: 5000 });
      console.log('✅ Guacamole main page is accessible');
      return { success: true, status: 'Main page accessible', endpoint: this.baseUrl };
    } catch (error) {
      console.error('❌ Guacamole is not accessible:', error.message);
      return { success: false, error: error.message };
    }
  }
}

module.exports = new GuacamoleService();

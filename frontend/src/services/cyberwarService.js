import axios from '../utils/axiosConfig';

/**
 * CyberWar API Service
 * Handles all API calls related to cyber-warfare matches, teams, and scoring
 */
class CyberWarService {
  
  // ===== ADMIN OPERATIONS =====
  
  /**
   * Perform admin action on user (activate/deactivate/delete)
   * @param {string} userId - ID of the user to perform action on
   * @param {string} action - Action to perform ('activate', 'deactivate', 'delete')
   */
  async adminUserAction(userId, action) {
    try {
      const response = await axios.post(`/admin/cyberwar/users/${userId}/${action}`);
      return response.data;
    } catch (error) {
      console.error(`Failed to ${action} user:`, error);
      throw error.response?.data || { error: `Failed to ${action} user` };
    }
  }

  // ===== TEAM OPERATIONS =====
  
  /**
   * Get all teams
   */
  async getTeams(params = {}) {
    try {
      const response = await axios.get('/teams', { params });
      return response.data;
    } catch (error) {
      console.error('Failed to fetch teams:', error);
      throw error.response?.data || { error: 'Failed to fetch teams' };
    }
  }

  /**
   * Get team details by ID
   */
  async getTeamById(teamId) {
    try {
      const response = await axios.get(`/teams/${teamId}`);
      return response.data;
    } catch (error) {
      console.error(`Failed to fetch team ${teamId}:`, error);
      throw error;
    }
  }

  /**
   * Create a new team
   * @param {Object} teamData - Team data including name and optional description
   * @returns {Promise<Object>} Created team data
   */
  async createTeam(teamData) {
    try {
      const response = await axios.post('/teams', teamData);
      return response.data;
    } catch (error) {
      console.error('Failed to create team:', error);
      throw error.response?.data || { error: 'Failed to create team' };
    }
  }

  /**
   * Join a team
   * @param {string|number} teamId - ID of the team to join
   * @param {string} [inviteCode] - Optional invite code for private teams
   * @returns {Promise<Object>} Updated team membership data
   */
  async joinTeam(teamId, inviteCode) {
    try {
      const response = await axios.post(`/teams/${teamId}/join`, { inviteCode });
      return response.data;
    } catch (error) {
      console.error(`Failed to join team ${teamId}:`, error);
      throw error.response?.data || { error: 'Failed to join team' };
    }
  }

  /**
   * Leave a team
   * @param {string|number} teamId - ID of the team to leave
   * @returns {Promise<Object>} Result of the leave operation
   */
  async leaveTeam(teamId) {
    try {
      const response = await axios.post(`/teams/${teamId}/leave`);
      return response.data;
    } catch (error) {
      console.error(`Failed to leave team ${teamId}:`, error);
      throw error.response?.data || { error: 'Failed to leave team' };
    }
  }

  /**
   * Transfer team ownership to another member
   * @param {string|number} teamId - ID of the team
   * @param {string|number} newOwnerId - ID of the new owner
   * @returns {Promise<Object>} Updated team data
   */
  async transferOwnership(teamId, newOwnerId) {
    try {
      const response = await axios.post(`/teams/${teamId}/transfer-ownership`, { newOwnerId });
      return response.data;
    } catch (error) {
      console.error(`Failed to transfer ownership of team ${teamId}:`, error);
      throw error.response?.data || { error: 'Failed to transfer ownership' };
    }
  }

  /**
   * Update team information
   * @param {string|number} teamId - ID of the team to update
   * @param {Object} updates - Team fields to update
   * @returns {Promise<Object>} Updated team data
   */
  async updateTeam(teamId, updates) {
    try {
      const response = await axios.put(`/teams/${teamId}`, updates);
      return response.data;
    } catch (error) {
      console.error(`Failed to update team ${teamId}:`, error);
      throw error.response?.data || { error: 'Failed to update team' };
    }
  }

  /**
   * Remove a member from the team
   * @param {string|number} teamId - ID of the team
   * @param {string|number} userId - ID of the user to remove
   * @returns {Promise<Object>} Result of the removal
   */
  async removeTeamMember(teamId, userId) {
    try {
      const response = await axios.delete(`/teams/${teamId}/members/${userId}`);
      return response.data;
    } catch (error) {
      console.error(`Failed to remove member ${userId} from team ${teamId}:`, error);
      throw error.response?.data || { error: 'Failed to remove team member' };
    }
  }

  /**
   * Generate a new invite code for the team
   * @param {string|number} teamId - ID of the team
   * @returns {Promise<Object>} New invite code and expiration
   */
  async generateInviteCode(teamId) {
    try {
      const response = await axios.post(`/teams/${teamId}/invite-code`);
      return response.data;
    } catch (error) {
      console.error(`Failed to generate invite code for team ${teamId}:`, error);
      throw error.response?.data || { error: 'Failed to generate invite code' };
    }
  }

  /**
   * Get user's team for a specific match
   */
  async getUserTeamForMatch(matchId) {
    try {
      const response = await axios.get(`/matches/${matchId}/user-team`);
      return response.data;
    } catch (error) {
      console.error(`Failed to fetch user team for match ${matchId}:`, error);
      // Return null if user is not in a team for this match
      if (error.response && error.response.status === 404) {
        return null;
      }
      throw error;
    }
  }

  /**
   * Get team statistics
   */
  async getTeamStats(teamId, timeRange = '30') {
    try {
      const response = await axios.get(`/teams/${teamId}/stats`, {
        params: { timeRange }
      });
      return response.data;
    } catch (error) {
      console.error(`Failed to fetch team stats for ${teamId}:`, error);
      throw error;
    }
  }

  /**
   * Get match history for a specific team
   * @param {string|number} teamId - ID of the team
   * @param {Object} [params] - Optional query parameters (page, limit, etc.)
   * @returns {Promise<Object>} Team's match history
   */
  async getTeamMatches(teamId, params = {}) {
    try {
      const response = await axios.get(`/teams/${teamId}/matches`, { params });
      return response.data;
    } catch (error) {
      console.error(`Failed to fetch matches for team ${teamId}:`, error);
      throw error.response?.data || { error: 'Failed to fetch team matches' };
    }
  }

  /**
   * Delete a team (admin only)
   * @param {string|number} teamId - ID of the team to delete
   * @returns {Promise<Object>} Delete confirmation
   */
  async deleteTeam(teamId) {
    try {
      const response = await axios.delete(`/teams/${teamId}`);
      return response.data;
    } catch (error) {
      console.error(`Failed to delete team ${teamId}:`, error);
      throw error.response?.data || { error: 'Failed to delete team' };
    }
  }

  /**
   * Add a member to a team (admin only)
   * @param {string|number} teamId - ID of the team
   * @param {string|number} userId - ID of the user to add
   * @returns {Promise<Object>} Updated team data
   */
  async addTeamMember(teamId, userId) {
    try {
      const response = await axios.post(`/teams/${teamId}/members`, { userId });
      return response.data;
    } catch (error) {
      console.error(`Failed to add member ${userId} to team ${teamId}:`, error);
      throw error.response?.data || { error: 'Failed to add team member' };
    }
  }

  // ===== MATCH OPERATIONS =====

  /**
   * Get all matches
   */
  async getMatches(params = {}) {
    try {
      const response = await axios.get('/matches', { params });
      return response.data;
    } catch (error) {
      console.error('Failed to fetch matches:', error);
      throw error;
    }
  }

  /**
   * Get active matches
   */
  async getActiveMatches() {
    try {
      const response = await axios.get('/matches/active');
      return response.data;
    } catch (error) {
      console.error('Failed to fetch active matches:', error);
      throw error;
    }
  }

  /**
   * Get match details by ID
   */
  async getMatchById(matchId) {
    try {
      const response = await axios.get(`/matches/${matchId}`);
      return response.data;
    } catch (error) {
      console.error(`Failed to fetch match ${matchId}:`, error);
      throw error.response?.data || { error: `Failed to fetch match ${matchId}` };
    }
  }

  /**
   * Create a new match (admin only)
   * @param {Object} matchData - Match data including name, description, duration, etc.
   * @returns {Promise<Object>} Created match data
   */
  async createMatch(matchData) {
    try {
      // Transform the frontend match data to match the backend's expected format
      const formattedMatchData = {
        name: matchData.name,
        description: matchData.description || '',
        matchType: matchData.matchType || 'attack_defend',
        duration: (matchData.duration || 120) * 60, // Convert minutes to seconds
        maxTeams: matchData.maxTeams || 4,
        autoScoring: true,
        packetCaptureEnabled: true,
        logAnalysisEnabled: false,
        elkIntegration: false,
        networkConfig: null,
        vmConfig: null, // Let backend handle VM configuration
        scoringRules: {
          flagCapture: 100,
          serviceUp: 10,
          serviceDown: -5,
          firstBlood: 50,
          slaViolation: -20
        },
        flags: [] // Let backend handle flag generation
      };

      console.log('Sending match creation request:', formattedMatchData);
      const response = await axios.post('/matches', formattedMatchData, {
        validateStatus: (status) => status < 500 // Don't throw on 4xx errors
      });
      
      if (response.status >= 400) {
        console.error('Failed to create match:', response.data);
        throw response.data.error || { message: 'Failed to create match' };
      }
      
      console.log('Match created successfully:', response.data);
      return response.data;
    } catch (error) {
      console.error('Failed to create match:', error);
      throw error;
    }
  }

  /**
   * Update an existing match (admin only)
   * @param {string|number} matchId - ID of the match to update
   * @param {Object} matchData - Updated match data
   * @returns {Promise<Object>} Updated match data
   */
  async updateMatch(matchId, matchData) {
    try {
      // Transform the frontend match data to match the backend's expected format
      const formattedMatchData = {
        name: matchData.name,
        description: matchData.description,
        matchType: matchData.matchType,
        maxTeams: matchData.maxTeams,
        startTime: matchData.startTime,
        endTime: matchData.endTime,
        status: matchData.status
      };

      console.log('Sending match update request:', formattedMatchData);
      const response = await axios.put(`/admin/cyberwar/matches/${matchId}`, formattedMatchData);
      
      console.log('Match updated successfully:', response.data);
      return response.data;
    } catch (error) {
      console.error('Failed to update match:', error);
      throw error;
    }
  }

  /**
   * Delete a match (admin only)
   * @param {string|number} matchId - ID of the match to delete
   * @returns {Promise<Object>} Delete confirmation
   */
  async deleteMatch(matchId) {
    try {
      console.log('Sending match delete request for ID:', matchId);
      const response = await axios.delete(`/admin/cyberwar/matches/${matchId}`);
      
      console.log('Match deleted successfully:', response.data);
      return response.data;
    } catch (error) {
      console.error('Failed to delete match:', error);
      throw error;
    }
  }

  /**
   * Start a match (admin only)
   */
  async startMatch(matchId) {
    try {
      const response = await axios.post(`/matches/${matchId}/start`);
      return response.data;
    } catch (error) {
      console.error(`Failed to start match ${matchId}:`, error);
      throw error;
    }
  }

  /**
   * End a match (admin only)
   */
  async endMatch(matchId, reason = 'admin_ended') {
    try {
      const response = await axios.post(`/matches/${matchId}/end`, { reason });
      return response.data;
    } catch (error) {
      console.error(`Failed to end match ${matchId}:`, error);
      throw error;
    }
  }

  /**
   * Control match actions (start/pause/resume/stop)
   */
  async controlMatch(matchId, action) {
    try {
      let response;
      switch (action) {
        case 'start':
          response = await axios.post(`/matches/${matchId}/start`);
          break;
        case 'pause':
          response = await axios.post(`/matches/${matchId}/pause`);
          break;
        case 'resume':
          response = await axios.post(`/matches/${matchId}/resume`);
          break;
        case 'stop':
          response = await axios.post(`/matches/${matchId}/end`, { reason: 'admin_stopped' });
          break;
        default:
          throw new Error(`Unknown action: ${action}`);
      }
      return response.data;
    } catch (error) {
      console.error(`Failed to ${action} match ${matchId}:`, error);
      throw error.response?.data || error;
    }
  }

  /**
   * Join a match with a team
   */
  async joinMatch(matchId, teamId) {
    try {
      const response = await axios.post(`/matches/${matchId}/join`, { teamId });
      return response.data;
    } catch (error) {
      console.error(`Failed to join match ${matchId} with team ${teamId}:`, error);
      throw error;
    }
  }

  /**
   * Leave a match
   */
  async leaveMatch(matchId) {
    try {
      const response = await axios.post(`/matches/${matchId}/leave`);
      return response.data;
    } catch (error) {
      console.error(`Failed to leave match ${matchId}:`, error);
      throw error;
    }
  }

  /**
   * Add teams to match (admin only)
   */
  async addTeamsToMatch(matchId, teamIds) {
    try {
      const response = await axios.post(`/matches/${matchId}/teams`, { teamIds });
      return response.data;
    } catch (error) {
      console.error(`Failed to add teams to match ${matchId}:`, error);
      throw error;
    }
  }

  // ===== SCORING OPERATIONS =====

  /**
   * Submit a cyber-warfare flag
   */
  async submitFlag(matchId, flagData) {
    try {
      const response = await axios.post(`/matches/${matchId}/flags/submit`, flagData);
      return response.data;
    } catch (error) {
      console.error('Failed to submit flag:', error);
      throw error;
    }
  }

  /**
   * Control VM (start/stop/restart)
   */
  async controlVM(vmId, action) {
    try {
      const response = await axios.post(`/proxmox/vms/${vmId}/${action}`);
      return response.data;
    } catch (error) {
      console.error(`Failed to ${action} VM ${vmId}:`, error);
      throw error;
    }
  }

  /**
   * Get match scoreboard
   */
  async getMatchScoreboard(matchId) {
    try {
      const response = await axios.get(`/matches/${matchId}/scoreboard`);
      return response.data;
    } catch (error) {
      console.error(`Failed to fetch scoreboard for match ${matchId}:`, error);
      throw error;
    }
  }

  /**
   * Get match flags
   */
  async getMatchFlags(matchId) {
    try {
      const response = await axios.get(`/matches/${matchId}/flags`);
      return response.data;
    } catch (error) {
      console.error(`Failed to fetch flags for match ${matchId}:`, error);
      throw error;
    }
  }

  /**
   * Get match events
   */
  async getMatchEvents(matchId, params = {}) {
    try {
      const response = await axios.get(`/flags/match/${matchId}/events`, { params });
      return response.data;
    } catch (error) {
      console.error(`Failed to fetch events for match ${matchId}:`, error);
      throw error;
    }
  }

  /**
   * Get leaderboard
   */
  async getLeaderboard(params = {}) {
    try {
      const response = await axios.get('/flags/leaderboard', { params });
      return response.data;
    } catch (error) {
      console.error('Failed to fetch leaderboard:', error);
      throw error;
    }
  }

  // ===== ADMIN OPERATIONS =====

  /**
   * Get admin dashboard statistics
   */
  async getAdminStats() {
    try {
      const response = await axios.get('/admin/cyberwar/stats');
      return response.data;
    } catch (error) {
      console.error('Failed to fetch admin stats:', error);
      throw error;
    }
  }

  // ===== FLAG MANAGEMENT (ADMIN) =====

  /**
   * Get all flags for admin
   * @param {Object} filters - Optional filters like matchId
   * @returns {Promise<Object>} Flags data
   */
  async getAdminFlags(filters = {}) {
    try {
      const params = new URLSearchParams(filters);
      const response = await axios.get(`/admin/cyberwar/flags?${params}`);
      return response.data;
    } catch (error) {
      console.error('Failed to fetch admin flags:', error);
      throw error;
    }
  }

  /**
   * Create a new flag (admin only)
   * @param {Object} flagData - Flag data
   * @returns {Promise<Object>} Created flag data
   */
  async createFlag(flagData) {
    try {
      const response = await axios.post('/admin/cyberwar/flags', flagData);
      return response.data;
    } catch (error) {
      console.error('Failed to create flag:', error);
      throw error;
    }
  }

  /**
   * Update an existing flag (admin only)
   * @param {string|number} flagId - ID of the flag to update
   * @param {Object} flagData - Updated flag data
   * @returns {Promise<Object>} Updated flag data
   */
  async updateFlag(flagId, flagData) {
    try {
      const response = await axios.put(`/admin/cyberwar/flags/${flagId}`, flagData);
      return response.data;
    } catch (error) {
      console.error('Failed to update flag:', error);
      throw error;
    }
  }

  /**
   * Delete a flag (admin only)
   * @param {string|number} flagId - ID of the flag to delete
   * @returns {Promise<Object>} Delete confirmation
   */
  async deleteFlag(flagId) {
    try {
      const response = await axios.delete(`/admin/cyberwar/flags/${flagId}`);
      return response.data;
    } catch (error) {
      console.error('Failed to delete flag:', error);
      throw error;
    }
  }

  /**
   * Get all users for admin
   */
  async getAdminUsers() {
    try {
      const response = await axios.get('/admin/cyberwar/users');
      return response.data;
    } catch (error) {
      console.error('Failed to fetch admin users:', error);
      throw error;
    }
  }

  /**
   * Get all flags for admin
   */
  async getAdminFlags() {
    try {
      const response = await axios.get('/admin/cyberwar/flags');
      return response.data;
    } catch (error) {
      console.error('Failed to fetch admin flags:', error);
      throw error;
    }
  }

  /**
   * Get all VMs for admin
   */
  async getAdminVMs() {
    try {
      const response = await axios.get('/admin/cyberwar/vms');
      return response.data;
    } catch (error) {
      console.error('Failed to fetch admin VMs:', error);
      throw error;
    }
  }

  // ===== VM OPERATIONS =====

  /**
   * Get Proxmox system status
   */
  async getProxmoxStatus() {
    try {
      const response = await axios.get('/proxmox/status');
      return response.data;
    } catch (error) {
      console.error('Failed to fetch Proxmox status:', error);
      throw error;
    }
  }

  /**
   * Get VM inventory
   */
  async getVMInventory() {
    try {
      const response = await axios.get('/proxmox/inventory');
      return response.data;
    } catch (error) {
      console.error('Failed to fetch VM inventory:', error);
      throw error;
    }
  }

  /**
   * Start VM
   */
  async startVM(vmId) {
    try {
      const response = await axios.post(`/proxmox/vms/${vmId}/start`);
      return response.data;
    } catch (error) {
      console.error(`Failed to start VM ${vmId}:`, error);
      throw error;
    }
  }

  /**
   * Stop VM
   */
  async stopVM(vmId) {
    try {
      const response = await axios.post(`/proxmox/vms/${vmId}/stop`);
      return response.data;
    } catch (error) {
      console.error(`Failed to stop VM ${vmId}:`, error);
      throw error;
    }
  }

  /**
   * Get match VM assignments for current user's team
   */
  async getMatchVMAssignments(matchId) {
    try {
      const response = await axios.get(`/proxmox/matches/${matchId}/my-assignments`);
      return response.data;
    } catch (error) {
      console.error(`Failed to fetch VM assignments for match ${matchId}:`, error);
      // Return empty array if no VMs assigned yet
      return { vms: [], totalVMs: 0 };
    }
  }

  // ===== UTILITY FUNCTIONS =====

  /**
   * Format event type for display
   */
  formatEventType(eventType) {
    const eventTypeMap = {
      'network_compromise': 'Network Compromise',
      'vulnerability_exploit': 'Vulnerability Exploit',
      'attack_success': 'Attack Success',
      'lateral_movement': 'Lateral Movement',
      'flag_capture': 'Flag Capture',
      'defense_action': 'Defense Action',
      'stealth_achievement': 'Stealth Achievement',
      'full_compromise': 'Full Compromise'
    };
    return eventTypeMap[eventType] || eventType.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
  }

  /**
   * Get event type color for UI
   */
  getEventTypeColor(eventType) {
    const colorMap = {
      'network_compromise': 'primary',
      'vulnerability_exploit': 'warning',
      'attack_success': 'success',
      'lateral_movement': 'info',
      'flag_capture': 'success',
      'defense_action': 'secondary',
      'stealth_achievement': 'purple',
      'full_compromise': 'danger'
    };
    return colorMap[eventType] || 'secondary';
  }

  /**
   * Format points for display
   */
  formatPoints(points) {
    return points ? `+${points}` : '0';
  }

  /**
   * Get time ago string
   */
  getTimeAgo(timestamp) {
    const now = new Date();
    const past = new Date(timestamp);
    const diffMs = now - past;
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMins / 60);
    const diffDays = Math.floor(diffHours / 24);

    if (diffMins < 1) return 'Just now';
    if (diffMins < 60) return `${diffMins}m ago`;
    if (diffHours < 24) return `${diffHours}h ago`;
    return `${diffDays}d ago`;
  }

  /**
   * Get vulnerability statistics for admin dashboard
   */
  async getVulnerabilityStats() {
    try {
      // Mock data for now - replace with actual API call when available
      return {
        totalVulnerabilities: 25,
        highSeverity: 8,
        mediumSeverity: 12,
        lowSeverity: 5,
        recentDiscoveries: []
      };
    } catch (error) {
      console.error('Failed to fetch vulnerability stats:', error);
      throw error.response?.data || { error: 'Failed to fetch vulnerability stats' };
    }
  }

  /**
   * Export admin data in various formats
   */
  async exportAdminData(type) {
    try {
      // Mock implementation - replace with actual API call when available
      console.log(`Exporting admin data of type: ${type}`);
      return { message: `${type} data export initiated` };
    } catch (error) {
      console.error('Failed to export admin data:', error);
      throw error.response?.data || { error: 'Failed to export admin data' };
    }
  }

  /**
   * Export scoreboard data
   */
  async exportScoreboard(matchId) {
    try {
      // Mock implementation - replace with actual API call when available
      console.log(`Exporting scoreboard for match: ${matchId}`);
      return { message: 'Scoreboard export initiated' };
    } catch (error) {
      console.error('Failed to export scoreboard:', error);
      throw error.response?.data || { error: 'Failed to export scoreboard' };
    }
  }
}

// Export singleton instance
const cyberwarService = new CyberWarService();
export default cyberwarService;

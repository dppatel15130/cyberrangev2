import axios from '../utils/axiosConfig';

/**
 * CyberWar API Service
 * Handles all API calls related to cyber-warfare matches, teams, and scoring
 */
class CyberWarService {
  
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
      throw error;
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
   */
  async createTeam(teamData) {
    try {
      const response = await axios.post('/teams', teamData);
      return response.data;
    } catch (error) {
      console.error('Failed to create team:', error);
      throw error;
    }
  }

  /**
   * Join a team
   */
  async joinTeam(teamId) {
    try {
      const response = await axios.post(`/teams/${teamId}/join`);
      return response.data;
    } catch (error) {
      console.error(`Failed to join team ${teamId}:`, error);
      throw error;
    }
  }

  /**
   * Leave a team
   */
  async leaveTeam(teamId) {
    try {
      const response = await axios.post(`/teams/${teamId}/leave`);
      return response.data;
    } catch (error) {
      console.error(`Failed to leave team ${teamId}:`, error);
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
      throw error;
    }
  }

  /**
   * Create a new match (admin only)
   */
  async createMatch(matchData) {
    try {
      const response = await axios.post('/matches', matchData);
      return response.data;
    } catch (error) {
      console.error('Failed to create match:', error);
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
  async submitFlag(flagData) {
    try {
      const response = await axios.post('/flags/cyberwar/submit', flagData);
      return response.data;
    } catch (error) {
      console.error('Failed to submit flag:', error);
      throw error;
    }
  }

  /**
   * Get match scoreboard
   */
  async getMatchScoreboard(matchId) {
    try {
      const response = await axios.get(`/flags/match/${matchId}/scoreboard`);
      return response.data;
    } catch (error) {
      console.error(`Failed to fetch scoreboard for match ${matchId}:`, error);
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
   * Get match VM assignments
   */
  async getMatchVMAssignments(matchId) {
    try {
      const response = await axios.get(`/proxmox/matches/${matchId}/assignments`);
      return response.data;
    } catch (error) {
      console.error(`Failed to fetch VM assignments for match ${matchId}:`, error);
      throw error;
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
}

// Export singleton instance
const cyberwarService = new CyberWarService();
export default cyberwarService;

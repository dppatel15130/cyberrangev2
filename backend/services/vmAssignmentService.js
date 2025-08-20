const { VM, User, Team, Match } = require('../models');
const { Op } = require('sequelize');

class VMAssignmentService {
  constructor() {
    this.vmPool = new Map();
    this.userAssignments = new Map();
    this.teamAssignments = new Map();
  }

  /**
   * Initialize VM pool with available VMs
   */
  async initializeVMPool() {
    try {
      console.log('Initializing VM assignment pool...');
      
      const vms = await VM.findAll({
        where: {
          status: 'running'
        }
      });

      // Clear existing pool
      this.vmPool.clear();

      // Categorize VMs by type and role
      vms.forEach(vm => {
        const vmKey = `${vm.vmId}_${vm.type || 'unknown'}_${vm.role || 'unknown'}`;
        this.vmPool.set(vmKey, {
          vmId: vm.vmId,
          ipAddress: vm.ipAddress,
          name: vm.name,
          type: vm.type || 'unknown',
          role: vm.role || 'unknown',
          isTarget: vm.isTarget || false,
          isAttacker: vm.isAttacker || false,
          status: 'available',
          assignedTo: null,
          assignedAt: null
        });
      });

      console.log(`✅ VM pool initialized with ${this.vmPool.size} VMs`);
      return true;
    } catch (error) {
      console.error('Error initializing VM pool:', error);
      return false;
    }
  }

  /**
   * Automatically assign VMs when user joins a team
   */
  async assignVMsToUser(userId, teamId, matchId) {
    try {
      console.log(`Assigning VMs to user ${userId} in team ${teamId} for match ${matchId}`);

      const user = await User.findByPk(userId);
      const team = await Team.findByPk(teamId);
      const match = await Match.findByPk(matchId);

      if (!user || !team || !match) {
        throw new Error('User, team, or match not found');
      }

      // Get match configuration
      const matchConfig = JSON.parse(match.matchConfig || '{}');
      const networkConfig = JSON.parse(match.networkConfig || '{}');

      // Determine VM requirements based on match type and user role
      const vmRequirements = this.getVMRequirementsForUser(user, team, match);

      const assignedVMs = [];

      for (const requirement of vmRequirements) {
        const vm = await this.assignVMToUser(userId, requirement);
        if (vm) {
          assignedVMs.push(vm);
        }
      }

      // Store assignment
      const assignmentKey = `${userId}_${teamId}_${matchId}`;
      this.userAssignments.set(assignmentKey, {
        userId,
        teamId,
        matchId,
        assignedVMs,
        assignedAt: new Date()
      });

      console.log(`✅ Assigned ${assignedVMs.length} VMs to user ${user.username}`);
      return {
        success: true,
        assignedVMs,
        message: `Assigned ${assignedVMs.length} VMs to user ${user.username}`
      };

    } catch (error) {
      console.error('Error assigning VMs to user:', error);
      return {
        success: false,
        error: error.message,
        assignedVMs: []
      };
    }
  }

  /**
   * Assign VMs to team when match becomes active
   */
  async assignVMsToTeam(teamId, matchId) {
    try {
      console.log(`Assigning VMs to team ${teamId} for match ${matchId}`);

      const team = await Team.findByPk(teamId, {
        include: [{ model: User, as: 'members' }]
      });
      const match = await Match.findByPk(matchId);

      if (!team || !match) {
        throw new Error('Team or match not found');
      }

      const teamVMs = [];

      // Assign VMs to each team member
      for (const member of team.members) {
        const userVMs = await this.assignVMsToUser(member.id, teamId, matchId);
        if (userVMs.success) {
          teamVMs.push(...userVMs.assignedVMs);
        }
      }

      // Store team assignment
      this.teamAssignments.set(`${teamId}_${matchId}`, {
        teamId,
        matchId,
        assignedVMs: teamVMs,
        assignedAt: new Date()
      });

      console.log(`✅ Assigned ${teamVMs.length} VMs to team ${team.name}`);
      return {
        success: true,
        assignedVMs: teamVMs,
        message: `Assigned ${teamVMs.length} VMs to team ${team.name}`
      };

    } catch (error) {
      console.error('Error assigning VMs to team:', error);
      return {
        success: false,
        error: error.message,
        assignedVMs: []
      };
    }
  }

  /**
   * Get VM requirements for a user based on match configuration
   */
  getVMRequirementsForUser(user, team, match) {
    const requirements = [];

    // Default requirements for cyber warfare match
    if (match.name.includes('Vulnerability Hunt') || match.name.includes('Cyber')) {
      // Each user gets an attacker VM
      requirements.push({
        type: 'kali',
        role: 'attacker',
        priority: 'high',
        description: 'Kali Linux attacker machine'
      });

      // Team gets shared access to target VM
      if (team.members && team.members.length > 0) {
        requirements.push({
          type: 'windows',
          role: 'target',
          priority: 'medium',
          description: 'Windows target server (shared)',
          shared: true
        });
      }
    }

    // Add custom requirements based on match configuration
    const matchConfig = JSON.parse(match.matchConfig || '{}');
    if (matchConfig.vmRequirements) {
      requirements.push(...matchConfig.vmRequirements);
    }

    return requirements;
  }

  /**
   * Assign a specific VM to a user
   */
  async assignVMToUser(userId, requirement) {
    try {
      // Find available VM matching requirements
      const availableVM = this.findAvailableVM(requirement);

      if (!availableVM) {
        console.warn(`No available VM found for requirement: ${requirement.type}/${requirement.role}`);
        return null;
      }

      // Mark VM as assigned
      availableVM.status = 'assigned';
      availableVM.assignedTo = userId;
      availableVM.assignedAt = new Date();

      // Update VM in database
      await VM.update(
        {
          assignedTo: userId,
          assignedAt: new Date(),
          status: 'assigned'
        },
        {
          where: { vmId: availableVM.vmId }
        }
      );

      console.log(`✅ Assigned VM ${availableVM.vmId} (${availableVM.name}) to user ${userId}`);

      return {
        vmId: availableVM.vmId,
        ipAddress: availableVM.ipAddress,
        name: availableVM.name,
        type: availableVM.type,
        role: availableVM.role,
        requirement: requirement
      };

    } catch (error) {
      console.error('Error assigning VM to user:', error);
      return null;
    }
  }

  /**
   * Find available VM matching requirements
   */
  findAvailableVM(requirement) {
    for (const [key, vm] of this.vmPool) {
      if (vm.status === 'available' &&
          (vm.type === requirement.type || requirement.type === 'any') &&
          (vm.role === requirement.role || requirement.role === 'any')) {
        return vm;
      }
    }
    return null;
  }

  /**
   * Get VMs assigned to a user
   */
  async getUserVMs(userId, matchId = null) {
    try {
      const where = { assignedTo: userId };
      // Note: matchId filtering is not available in current VM model
      // We'll use the in-memory assignments instead

      const vms = await VM.findAll({ where });
      return vms;
    } catch (error) {
      console.error('Error getting user VMs:', error);
      return [];
    }
  }

  /**
   * Get VMs assigned to a team
   */
  async getTeamVMs(teamId, matchId) {
    try {
      const team = await Team.findByPk(teamId, {
        include: [{ model: User, as: 'members' }]
      });

      if (!team) return [];

      const teamVMs = [];
      for (const member of team.members) {
        const userVMs = await this.getUserVMs(member.id, matchId);
        teamVMs.push(...userVMs);
      }

      return teamVMs;
    } catch (error) {
      console.error('Error getting team VMs:', error);
      return [];
    }
  }

  /**
   * Release VMs when user leaves or match ends
   */
  async releaseUserVMs(userId, matchId) {
    try {
      console.log(`Releasing VMs for user ${userId} from match ${matchId}`);

      const vms = await VM.findAll({
        where: { assignedTo: userId }
      });

      for (const vm of vms) {
        await vm.update({
          assignedTo: null,
          assignedAt: null,
          status: 'available'
        });

        // Update pool
        const vmKey = `${vm.vmId}_${vm.type || 'unknown'}_${vm.role || 'unknown'}`;
        if (this.vmPool.has(vmKey)) {
          this.vmPool.get(vmKey).status = 'available';
          this.vmPool.get(vmKey).assignedTo = null;
          this.vmPool.get(vmKey).assignedAt = null;
        }
      }

      // Remove assignment record
      const assignmentKey = `${userId}_${matchId}`;
      this.userAssignments.delete(assignmentKey);

      console.log(`✅ Released ${vms.length} VMs from user ${userId}`);
      return true;

    } catch (error) {
      console.error('Error releasing user VMs:', error);
      return false;
    }
  }

  /**
   * Get VM pool status
   */
  getVMPoolStatus() {
    const status = {
      total: this.vmPool.size,
      available: 0,
      assigned: 0,
      byType: {},
      byRole: {}
    };

    for (const [key, vm] of this.vmPool) {
      if (vm.status === 'available') {
        status.available++;
      } else {
        status.assigned++;
      }

      // Count by type
      status.byType[vm.type] = (status.byType[vm.type] || 0) + 1;
      status.byRole[vm.role] = (status.byRole[vm.role] || 0) + 1;
    }

    return status;
  }
}

module.exports = new VMAssignmentService();

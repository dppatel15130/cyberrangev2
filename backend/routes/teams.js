const express = require('express');
const { Team, User, Match, ScoringEvent } = require('../models');
const { auth: authenticateToken, admin: requireAdmin } = require('../middleware/auth');
const { Op } = require('sequelize');
const router = express.Router();

// Get all teams with optional filtering
router.get('/', authenticateToken, async (req, res) => {
  try {
    const { page = 1, limit = 20, search, status } = req.query;
    const offset = (page - 1) * limit;
    
    const where = {};
    
    // Search by team name
    if (search) {
      where.name = { [Op.iLike]: `%${search}%` };
    }
    
    // Filter by status if provided
    if (status) {
      where.isActive = status === 'active';
    }

    const teams = await Team.findAndCountAll({
      where,
      include: [
        {
          model: User,
          as: 'members',
          attributes: ['id', 'username', 'email', 'role'],
          through: { attributes: [] }
        },
        {
          model: Match,
          as: 'matches',
          attributes: ['id', 'name', 'status', 'matchType'],
          through: { attributes: [] }
        }
      ],
      order: [['createdAt', 'DESC']],
      limit: parseInt(limit),
      offset: parseInt(offset)
    });

    const teamsWithStats = teams.rows.map(team => ({
      ...team.toJSON(),
      memberCount: team.members.length,
      activeMatches: team.matches.filter(m => m.status === 'active').length,
      totalMatches: team.matches.length
    }));

    res.json({
      teams: teamsWithStats,
      pagination: {
        total: teams.count,
        pages: Math.ceil(teams.count / limit),
        currentPage: parseInt(page),
        hasNext: offset + limit < teams.count,
        hasPrev: page > 1
      }
    });
  } catch (error) {
    console.error('Error fetching teams:', error);
    res.status(500).json({ error: 'Failed to fetch teams' });
  }
});

// Get available teams for match assignment
router.get('/available', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { matchId } = req.query;
    
    let excludeTeamIds = [];
    if (matchId) {
      // Get teams already assigned to this match
      const match = await Match.findByPk(matchId, {
        include: [{ model: Team, as: 'teams', attributes: ['id'] }]
      });
      if (match) {
        excludeTeamIds = match.teams.map(t => t.id);
      }
    }

    const where = {
      isActive: true
    };
    
    if (excludeTeamIds.length > 0) {
      where.id = { [Op.notIn]: excludeTeamIds };
    }

    const availableTeams = await Team.findAll({
      where,
      include: [
        {
          model: User,
          as: 'members',
          attributes: ['id', 'username'],
          through: { attributes: [] }
        }
      ],
      order: [['name', 'ASC']]
    });

    res.json(
      availableTeams.map(team => ({
        id: team.id,
        name: team.name,
        color: team.color,
        memberCount: team.members.length,
        currentPoints: team.currentPoints,
        totalFlags: team.totalFlags
      }))
    );
  } catch (error) {
    console.error('Error fetching available teams:', error);
    res.status(500).json({ error: 'Failed to fetch available teams' });
  }
});

// Get specific team details
router.get('/:id', authenticateToken, async (req, res) => {
  try {
    const team = await Team.findByPk(req.params.id, {
      include: [
        {
          model: User,
          as: 'members',
          attributes: ['id', 'username', 'email', 'role'],
          through: { attributes: [] }
        },
        {
          model: Match,
          as: 'matches',
          attributes: ['id', 'name', 'status', 'matchType', 'startTime', 'endTime'],
          through: { attributes: [] },
          include: [
            {
              model: User,
              as: 'creator',
              attributes: ['id', 'username']
            }
          ]
        },
        {
          model: ScoringEvent,
          as: 'scoringEvents',
          attributes: ['id', 'eventType', 'finalPoints', 'description', 'createdAt', 'matchId'],
          order: [['createdAt', 'DESC']],
          limit: 50,
          include: [
            {
              model: Match,
              as: 'match',
              attributes: ['id', 'name']
            }
          ]
        }
      ]
    });

    if (!team) {
      return res.status(404).json({ error: 'Team not found' });
    }

    // Calculate team statistics
    const statistics = {
      totalMatches: team.matches.length,
      activeMatches: team.matches.filter(m => m.status === 'active').length,
      completedMatches: team.matches.filter(m => m.status === 'completed').length,
      totalEvents: team.scoringEvents.length,
      averagePointsPerMatch: team.matches.length > 0 
        ? team.currentPoints / team.matches.length 
        : 0,
      eventTypeBreakdown: team.scoringEvents.reduce((breakdown, event) => {
        breakdown[event.eventType] = (breakdown[event.eventType] || 0) + 1;
        return breakdown;
      }, {}),
      recentActivity: team.scoringEvents.slice(0, 10)
    };

    res.json({
      ...team.toJSON(),
      statistics
    });
  } catch (error) {
    console.error('Error fetching team:', error);
    res.status(500).json({ error: 'Failed to fetch team details' });
  }
});

// Create new team
router.post('/', authenticateToken, async (req, res) => {
  try {
    const {
      name,
      description,
      color,
      isPublic = false,
      maxMembers = 4
    } = req.body;

    // Validate required fields
    if (!name) {
      return res.status(400).json({ error: 'Team name is required' });
    }

    // Check if team name already exists
    const existingTeam = await Team.findOne({ where: { name } });
    if (existingTeam) {
      return res.status(400).json({ error: 'Team name already exists' });
    }

    // Generate random color if not provided
    const teamColor = color || '#' + Math.floor(Math.random()*16777215).toString(16);

    const team = await Team.create({
      name,
      description,
      color: teamColor,
      isPublic,
      maxMembers,
      createdBy: req.user.id,
      currentPoints: 0,
      totalFlags: 0,
      isActive: true
    });

    // Add creator as team captain - simplified without joinedAt
    await team.addMember(req.user.id);

    const teamWithMembers = await Team.findByPk(team.id, {
      include: [
        {
          model: User,
          as: 'members',
          attributes: ['id', 'username', 'email', 'role'],
          through: { attributes: [] }
        }
      ]
    });

    res.status(201).json(teamWithMembers);
  } catch (error) {
    console.error('Error creating team:', error);
    res.status(500).json({ error: 'Failed to create team' });
  }
});

// Update team
router.put('/:id', authenticateToken, async (req, res) => {
  try {
    const team = await Team.findByPk(req.params.id, {
      include: [
        {
          model: User,
          as: 'members',
          attributes: ['id'],
          through: { attributes: [] }
        }
      ]
    });

    if (!team) {
      return res.status(404).json({ error: 'Team not found' });
    }

    // Check if user is team member or admin
    const isTeamMember = team.members.some(member => member.id === req.user.id);
    const isAdmin = req.user.role === 'admin';
    
    if (!isTeamMember && !isAdmin) {
      return res.status(403).json({ error: 'Not authorized to update this team' });
    }

    const allowedUpdates = ['name', 'description', 'color', 'isPublic', 'maxMembers'];
    const updates = {};
    
    allowedUpdates.forEach(field => {
      if (req.body[field] !== undefined) {
        updates[field] = req.body[field];
      }
    });

    // Check if name already exists (if being updated)
    if (updates.name && updates.name !== team.name) {
      const existingTeam = await Team.findOne({ 
        where: { name: updates.name, id: { [Op.not]: team.id } } 
      });
      if (existingTeam) {
        return res.status(400).json({ error: 'Team name already exists' });
      }
    }

    await team.update(updates);

    const updatedTeam = await Team.findByPk(req.params.id, {
      include: [
        {
          model: User,
          as: 'members',
          attributes: ['id', 'username', 'email', 'role'],
          through: { attributes: [] }
        }
      ]
    });

    res.json(updatedTeam);
  } catch (error) {
    console.error('Error updating team:', error);
    res.status(500).json({ error: 'Failed to update team' });
  }
});

// Join team
router.post('/:id/join', authenticateToken, async (req, res) => {
  try {
    const team = await Team.findByPk(req.params.id, {
      include: [
        {
          model: User,
          as: 'members',
          attributes: ['id'],
          through: { attributes: [] }
        }
      ]
    });

    if (!team) {
      return res.status(404).json({ error: 'Team not found' });
    }

    if (!team.isActive) {
      return res.status(400).json({ error: 'Team is not active' });
    }

    // Check if user is already a member
    const isAlreadyMember = team.members.some(member => member.id === req.user.id);
    if (isAlreadyMember) {
      return res.status(400).json({ error: 'Already a member of this team' });
    }

    // Check team capacity
    if (team.members.length >= team.maxMembers) {
      return res.status(400).json({ error: 'Team is at maximum capacity' });
    }

    // Check if user is already in another team (optional business rule)
    const userTeams = await Team.findAll({
      include: [
        {
          model: User,
          as: 'members',
          where: { id: req.user.id },
          attributes: ['id']
        }
      ],
      where: { isActive: true }
    });

    if (userTeams.length > 0) {
      return res.status(400).json({ 
        error: 'Already a member of another active team. Leave current team first.' 
      });
    }

    // Add user to team - simplified without joinedAt
    await team.addMember(req.user.id);

    const updatedTeam = await Team.findByPk(req.params.id, {
      include: [
        {
          model: User,
          as: 'members',
          attributes: ['id', 'username', 'role'],
          through: { attributes: [] } // Remove joinedAt reference
        }
      ]
    });

    res.json({
      message: 'Successfully joined team',
      team: updatedTeam
    });
  } catch (error) {
    console.error('Error joining team:', error);
    res.status(500).json({ error: 'Failed to join team' });
  }
});

// Leave team
router.post('/:id/leave', authenticateToken, async (req, res) => {
  try {
    const team = await Team.findByPk(req.params.id, {
      include: [
        {
          model: User,
          as: 'members',
          attributes: ['id'],
          through: { attributes: [] }
        }
      ]
    });

    if (!team) {
      return res.status(404).json({ error: 'Team not found' });
    }

    // Check if user is a member
    const isMember = team.members.some(member => member.id === req.user.id);
    if (!isMember) {
      return res.status(400).json({ error: 'Not a member of this team' });
    }

    // Check if team is in active matches
    const activeMatches = await Match.findAll({
      include: [
        {
          model: Team,
          as: 'teams',
          where: { id: team.id }
        }
      ],
      where: { status: 'active' }
    });

    if (activeMatches.length > 0) {
      return res.status(400).json({ 
        error: 'Cannot leave team during active matches' 
      });
    }

    // Remove user from team
    await team.removeMember(req.user.id);

    // If team is now empty, deactivate it
    const remainingMembers = await team.countMembers();
    if (remainingMembers === 0) {
      await team.update({ isActive: false });
    }

    res.json({ message: 'Successfully left team' });
  } catch (error) {
    console.error('Error leaving team:', error);
    res.status(500).json({ error: 'Failed to leave team' });
  }
});

// Add member to team (admin or team captain)
router.post('/:id/members', authenticateToken, async (req, res) => {
  try {
    const { userId } = req.body;

    if (!userId) {
      return res.status(400).json({ error: 'User ID is required' });
    }

    const team = await Team.findByPk(req.params.id, {
      include: [
        {
          model: User,
          as: 'members',
          attributes: ['id'],
          through: { attributes: [] }
        }
      ]
    });

    if (!team) {
      return res.status(404).json({ error: 'Team not found' });
    }

    // Check permissions (admin or team member)
    const isTeamMember = team.members.some(member => member.id === req.user.id);
    const isAdmin = req.user.role === 'admin';
    
    if (!isTeamMember && !isAdmin) {
      return res.status(403).json({ error: 'Not authorized to add members to this team' });
    }

    // Check if user exists
    const targetUser = await User.findByPk(userId);
    if (!targetUser) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Check if user is already a member
    const isAlreadyMember = team.members.some(member => member.id === userId);
    if (isAlreadyMember) {
      return res.status(400).json({ error: 'User is already a member of this team' });
    }

    // Check team capacity
    if (team.members.length >= team.maxMembers) {
      return res.status(400).json({ error: 'Team is at maximum capacity' });
    }

    // Add user to team - simplified without joinedAt
    await team.addMember(userId);

    const updatedTeam = await Team.findByPk(req.params.id, {
      include: [
        {
          model: User,
          as: 'members',
          attributes: ['id', 'username', 'email', 'role'],
          through: { attributes: [] }
        }
      ]
    });

    res.json({
      message: 'Member added successfully',
      team: updatedTeam
    });
  } catch (error) {
    console.error('Error adding team member:', error);
    res.status(500).json({ error: 'Failed to add team member' });
  }
});

// Remove member from team (admin or team captain)
router.delete('/:id/members/:userId', authenticateToken, async (req, res) => {
  try {
    const { userId } = req.params;

    const team = await Team.findByPk(req.params.id, {
      include: [
        {
          model: User,
          as: 'members',
          attributes: ['id'],
          through: { attributes: [] }
        }
      ]
    });

    if (!team) {
      return res.status(404).json({ error: 'Team not found' });
    }

    // Check permissions (admin, team member, or removing yourself)
    const isTeamMember = team.members.some(member => member.id === req.user.id);
    const isAdmin = req.user.role === 'admin';
    const isRemovingSelf = req.user.id === parseInt(userId);
    
    if (!isTeamMember && !isAdmin && !isRemovingSelf) {
      return res.status(403).json({ error: 'Not authorized to remove members from this team' });
    }

    // Check if user is a member
    const isMember = team.members.some(member => member.id === parseInt(userId));
    if (!isMember) {
      return res.status(400).json({ error: 'User is not a member of this team' });
    }

    // Check if team is in active matches
    const activeMatches = await Match.findAll({
      include: [
        {
          model: Team,
          as: 'teams',
          where: { id: team.id }
        }
      ],
      where: { status: 'active' }
    });

    if (activeMatches.length > 0) {
      return res.status(400).json({ 
        error: 'Cannot remove members during active matches' 
      });
    }

    // Remove user from team
    await team.removeMember(userId);

    // If team is now empty, deactivate it
    const remainingMembers = await team.countMembers();
    if (remainingMembers === 0) {
      await team.update({ isActive: false });
    }

    const updatedTeam = await Team.findByPk(req.params.id, {
      include: [
        {
          model: User,
          as: 'members',
          attributes: ['id', 'username', 'email', 'role'],
          through: { attributes: [] }
        }
      ]
    });

    res.json({
      message: 'Member removed successfully',
      team: updatedTeam
    });
  } catch (error) {
    console.error('Error removing team member:', error);
    res.status(500).json({ error: 'Failed to remove team member' });
  }
});

// Get all matches for a specific team
router.get('/:id/matches', authenticateToken, async (req, res) => {
  try {
    const { page = 1, limit = 20, status } = req.query;
    const offset = (page - 1) * limit;
    
    const where = {};
    
    // Filter by status if provided
    if (status) {
      where.status = status;
    }

    const matches = await Match.findAndCountAll({
      include: [
        {
          model: Team,
          as: 'teams',
          where: { id: req.params.id },
          attributes: [],
          through: { attributes: [] }
        },
        {
          model: User,
          as: 'creator',
          attributes: ['id', 'username']
        }
      ],
      where,
      order: [['startTime', 'DESC']],
      limit: parseInt(limit),
      offset: parseInt(offset)
    });

    res.json({
      matches: matches.rows,
      pagination: {
        total: matches.count,
        pages: Math.ceil(matches.count / limit),
        currentPage: parseInt(page),
        hasNext: offset + limit < matches.count,
        hasPrev: page > 1
      }
    });
  } catch (error) {
    console.error('Error fetching team matches:', error);
    res.status(500).json({ error: 'Failed to fetch team matches' });
  }
});

// Get team performance statistics
router.get('/:id/stats', authenticateToken, async (req, res) => {
  try {
    const { timeRange = '30' } = req.query; // days
    const daysAgo = parseInt(timeRange);
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - daysAgo);

    const team = await Team.findByPk(req.params.id);
    if (!team) {
      return res.status(404).json({ error: 'Team not found' });
    }

    // Get scoring events within time range
    const scoringEvents = await ScoringEvent.findAll({
      where: {
        teamId: req.params.id,
        createdAt: { [Op.gte]: startDate },
        isActive: true
      },
      include: [
        {
          model: Match,
          as: 'match',
          attributes: ['id', 'name', 'matchType']
        }
      ],
      order: [['createdAt', 'ASC']]
    });

    // Get matches within time range
    const matches = await Match.findAll({
      include: [
        {
          model: Team,
          as: 'teams',
          where: { id: req.params.id },
          attributes: []
        }
      ],
      where: {
        startTime: { [Op.gte]: startDate }
      },
      attributes: ['id', 'name', 'status', 'startTime', 'endTime', 'matchType']
    });

    // Calculate statistics
    const stats = {
      timeRange: `${daysAgo} days`,
      totalMatches: matches.length,
      totalEvents: scoringEvents.length,
      totalPoints: scoringEvents.reduce((sum, event) => sum + event.finalPoints, 0),
      averagePointsPerEvent: scoringEvents.length > 0 
        ? scoringEvents.reduce((sum, event) => sum + event.finalPoints, 0) / scoringEvents.length 
        : 0,
      
      // Event type breakdown
      eventTypeStats: scoringEvents.reduce((stats, event) => {
        if (!stats[event.eventType]) {
          stats[event.eventType] = { count: 0, totalPoints: 0 };
        }
        stats[event.eventType].count++;
        stats[event.eventType].totalPoints += event.finalPoints;
        return stats;
      }, {}),

      // Match type performance
      matchTypeStats: matches.reduce((stats, match) => {
        if (!stats[match.matchType]) {
          stats[match.matchType] = { count: 0, completed: 0 };
        }
        stats[match.matchType].count++;
        if (match.status === 'completed') {
          stats[match.matchType].completed++;
        }
        return stats;
      }, {}),

      // Daily activity
      dailyActivity: scoringEvents.reduce((daily, event) => {
        const date = event.createdAt.toISOString().split('T')[0];
        if (!daily[date]) {
          daily[date] = { events: 0, points: 0 };
        }
        daily[date].events++;
        daily[date].points += event.finalPoints;
        return daily;
      }, {}),

      // Recent performance trend
      recentEvents: scoringEvents.slice(-10).map(event => ({
        date: event.createdAt,
        type: event.eventType,
        points: event.finalPoints,
        match: event.match.name
      }))
    };

    res.json(stats);
  } catch (error) {
    console.error('Error fetching team stats:', error);
    res.status(500).json({ error: 'Failed to fetch team statistics' });
  }
});

// Deactivate team (admin only)
router.post('/:id/deactivate', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const team = await Team.findByPk(req.params.id);
    if (!team) {
      return res.status(404).json({ error: 'Team not found' });
    }

    // Check if team is in active matches
    const activeMatches = await Match.findAll({
      include: [
        {
          model: Team,
          as: 'teams',
          where: { id: team.id }
        }
      ],
      where: { status: 'active' }
    });

    if (activeMatches.length > 0) {
      return res.status(400).json({ 
        error: 'Cannot deactivate team during active matches' 
      });
    }

    await team.update({ isActive: false });

    res.json({ message: 'Team deactivated successfully' });
  } catch (error) {
    console.error('Error deactivating team:', error);
    res.status(500).json({ error: 'Failed to deactivate team' });
  }
});

// Reactivate team (admin only)
router.post('/:id/reactivate', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const team = await Team.findByPk(req.params.id);
    if (!team) {
      return res.status(404).json({ error: 'Team not found' });
    }

    await team.update({ isActive: true });

    res.json({ message: 'Team reactivated successfully' });
  } catch (error) {
    console.error('Error reactivating team:', error);
    res.status(500).json({ error: 'Failed to reactivate team' });
  }
});

// Delete team (admin only, only if no matches)
router.delete('/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const team = await Team.findByPk(req.params.id, {
      include: [
        {
          model: Match,
          as: 'matches',
          attributes: ['id']
        }
      ]
    });

    if (!team) {
      return res.status(404).json({ error: 'Team not found' });
    }

    if (team.matches.length > 0) {
      return res.status(400).json({ 
        error: 'Cannot delete team with match history. Deactivate instead.' 
      });
    }

    // Remove all members first
    await team.setMembers([]);

    // Delete all scoring events
    await ScoringEvent.destroy({ where: { teamId: team.id } });

    // Delete the team
    await team.destroy();

    res.json({ message: 'Team deleted successfully' });
  } catch (error) {
    console.error('Error deleting team:', error);
    res.status(500).json({ error: 'Failed to delete team' });
  }
});

module.exports = router;
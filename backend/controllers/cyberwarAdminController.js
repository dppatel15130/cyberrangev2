const { User, VM, Lab, Log, Match, Team, FlagSubmission, Flag } = require('../models');
const { Op } = require('sequelize');
const bcrypt = require('bcryptjs');

/**
 * Get admin dashboard statistics
 */
exports.getAdminStats = async (req, res) => {
  try {
    const [totalUsers, totalLabs, totalVMs] = await Promise.all([
      User.count(),
      Lab.count(),
      VM.count()
    ]);

    // Example: fetch last 10 log entries (if you have a Log model)
    let recentActivity = [];
    if (Log) {
      recentActivity = await Log.findAll({
        order: [['createdAt', 'DESC']],
        limit: 10
      });
    }

    const systemHealth = {
      cpu: Math.floor(Math.random() * 30) + 70,
      memory: Math.floor(Math.random() * 40) + 60,
      storage: Math.floor(Math.random() * 50) + 50,
      status: 'healthy'
    };

    res.json({
      stats: {
        totalUsers,
        totalLabs,
        totalVMs,
        systemHealth
      },
      recentActivity,
      leaderboard: [] // implement later if you want points/leaderboards
    });
  } catch (error) {
    console.error('Error in getAdminStats:', error);
    res.status(500).json({ error: 'Failed to fetch admin statistics' });
  }
};

/**
 * Get all users for admin
 */
exports.getAdminUsers = async (req, res) => {
  try {
    const { page = 1, limit = 20, search = '' } = req.query;
    const offset = (page - 1) * limit;

    const whereClause = {};
    if (search) {
      whereClause[Op.or] = [
        { username: { [Op.like]: `%${search}%` } },
        { email: { [Op.like]: `%${search}%` } }
      ];
    }

    const { count, rows: users } = await User.findAndCountAll({
      where: whereClause,
      attributes: ['id', 'username', 'email', 'role', 'isActive', 'createdAt', 'updatedAt'],
      limit: parseInt(limit),
      offset: parseInt(offset),
      order: [['createdAt', 'DESC']]
    });

    res.json({
      users,
      pagination: {
        total: count,
        page: parseInt(page),
        pages: Math.ceil(count / limit),
        limit: parseInt(limit)
      }
    });
  } catch (error) {
    console.error('Error in getAdminUsers:', error);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
};

/**
 * Get all flags for admin
 */
exports.getAdminFlags = async (req, res) => {
  try {
    // If you don’t have FlagSubmission model yet, return dummy
    res.json({
      flags: [],
      pagination: {
        total: 0,
        page: 1,
        pages: 1,
        limit: 20
      }
    });
  } catch (error) {
    console.error('Error in getAdminFlags:', error);
    res.status(500).json({ error: 'Failed to fetch flag submissions' });
  }
};

/**
 * Get all VMs for admin
 */
exports.getAdminVMs = async (req, res) => {
  try {
    const vms = await VM.findAll({
      include: [
        { model: User, as: 'user', attributes: ['id', 'username'] },
        { model: Lab, as: 'lab', attributes: ['id', 'name'] }
      ],
      order: [['createdAt', 'DESC']]
    });

    res.json({ vms });
  } catch (error) {
    console.error('Error in getAdminVMs:', error);
    res.status(500).json({ error: 'Failed to fetch VMs', details: error.message });
  }
};
// Add this method to your cyberwarAdminController.js

/**
 * Get admin dashboard statistics for cyberwar
 */
exports.getAdminStats = async (req, res) => {
  try {
    // Get real statistics from the database
    const [
      totalMatches,
      activeMatches,
      completedMatches,
      totalTeams,
      totalUsers,
      totalFlags,
      activeFlags,
      capturedFlags,
      totalVMs,
      runningVMs,
      stoppedVMs
    ] = await Promise.all([
      Match.count(),
      Match.count({ where: { status: 'active' } }),
      Match.count({ where: { status: 'finished' } }),
      Team.count(),
      User.count(),
      Flag.count(),
      Flag.count({ where: { isActive: true } }),
      Flag.count({ where: { capturedBy: { [Op.ne]: null } } }),
      VM.count(),
      VM.count({ where: { status: 'running' } }),
      VM.count({ where: { status: 'stopped' } })
    ]);

    const stats = {
      totalMatches,
      activeMatches,
      completedMatches,
      totalTeams,
      totalUsers,
      totalFlags,
      activeFlags,
      capturedFlags,
      totalVMs,
      runningVMs,
      stoppedVMs,
      alerts: [
        {
          type: 'info',
          message: 'Cyberwar system is ready for competition'
        }
      ]
    };
    
    res.json(stats);
  } catch (error) {
    console.error('Error in getAdminStats:', error);
    res.status(500).json({ error: 'Failed to fetch admin statistics' });
  }
};
/**
 * Handle user actions (activate/deactivate/delete)
 */
exports.userAction = async (req, res) => {
  try {
    const { userId, action } = req.params;
    
    // Find the user
    const user = await User.findByPk(userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Perform the requested action
    switch (action) {
      case 'activate':
        user.isActive = true;
        await user.save();
        return res.json({ message: 'User activated successfully' });
        
      case 'deactivate':
        user.isActive = false;
        await user.save();
        return res.json({ message: 'User deactivated successfully' });
        
      case 'delete':
        await user.destroy();
        return res.json({ message: 'User deleted successfully' });
        
      default:
        return res.status(400).json({ error: 'Invalid action' });
    }
  } catch (error) {
    console.error('Error in userAction:', error);
    res.status(500).json({ error: 'Failed to perform user action' });
  }
};

/**
 * Get all matches for admin
 */
exports.getAdminMatches = async (req, res) => {
  try {
    const matches = await Match.findAll({
      include: [
        {
          model: Team,
          as: 'teams',
          attributes: ['id', 'name', 'color', 'currentPoints'],
          through: { attributes: [] }
        },
        {
          model: User,
          as: 'creator',
          attributes: ['id', 'username']
        }
      ],
      order: [['createdAt', 'DESC']]
    });

    res.json({ matches });
  } catch (error) {
    console.error('Error in getAdminMatches:', error);
    res.status(500).json({ error: 'Failed to fetch matches' });
  }
};

/**
 * Get all teams for admin
 */
exports.getAdminTeams = async (req, res) => {
  try {
    const teams = await Team.findAll({
      include: [
        {
          model: User,
          as: 'members',
          attributes: ['id', 'username', 'role'],
          through: { attributes: [] }
        },
        {
          model: Match,
          as: 'matches',
          attributes: ['id', 'name', 'status'],
          through: { attributes: [] }
        }
      ],
      order: [['createdAt', 'DESC']]
    });

    res.json({ teams });
  } catch (error) {
    console.error('Error in getAdminTeams:', error);
    res.status(500).json({ error: 'Failed to fetch teams' });
  }
};

/**
 * Create new match (admin only)
 */
exports.createMatch = async (req, res) => {
  try {
    const { name, description, matchType, maxTeams, startTime, endTime, duration } = req.body;

    const match = await Match.create({
      name,
      description,
      matchType: matchType || 'capture_flag',
      maxTeams: maxTeams || 10,
      duration: duration ? duration * 60 : 3600, // Convert minutes to seconds
      startTime: startTime ? new Date(startTime) : null,
      endTime: endTime ? new Date(endTime) : null,
      status: 'waiting',
      createdBy: req.user.id
    });

    const matchWithDetails = await Match.findByPk(match.id, {
      include: [
        {
          model: User,
          as: 'creator',
          attributes: ['id', 'username']
        }
      ]
    });

    res.status(201).json({ 
      message: 'Match created successfully', 
      match: matchWithDetails 
    });
  } catch (error) {
    console.error('Error in createMatch:', error);
    res.status(500).json({ error: 'Failed to create match' });
  }
};

/**
 * Create new flag (admin only)
 */
exports.createFlag = async (req, res) => {
  try {
    const { matchId, name, description, flagValue, points, category, difficulty, hints } = req.body;

    // Validate required fields
    if (!matchId || !name || !flagValue || !points) {
      return res.status(400).json({ 
        error: 'Match ID, name, flag value, and points are required' 
      });
    }

    // Check if match exists
    const match = await Match.findByPk(matchId);
    if (!match) {
      return res.status(404).json({ error: 'Match not found' });
    }

    // Check if flag value already exists in this match
    const existingFlag = await Flag.findOne({
      where: { matchId, flagValue: flagValue.trim() }
    });

    if (existingFlag) {
      return res.status(409).json({ 
        error: 'A flag with this value already exists in this match' 
      });
    }

    // Create the flag
    const flag = await Flag.create({
      matchId,
      name: name.trim(),
      description: description?.trim() || null,
      flagValue: flagValue.trim(),
      points: parseInt(points),
      category: category || 'misc',
      difficulty: difficulty || 'beginner',
      hints: hints || [],
      createdBy: req.user.id,
      isActive: true
    });

    // Fetch the created flag with associations
    const createdFlag = await Flag.findByPk(flag.id, {
      include: [
        { model: Match, as: 'match', attributes: ['id', 'name'] },
        { model: User, as: 'creator', attributes: ['id', 'username'] }
      ]
    });

    res.status(201).json({ 
      message: 'Flag created successfully', 
      flag: createdFlag 
    });
  } catch (error) {
    console.error('Error in createFlag:', error);
    res.status(500).json({ error: 'Failed to create flag' });
  }
};

/**
 * Get all flags for admin
 */
exports.getAdminFlags = async (req, res) => {
  try {
    const { matchId } = req.query;
    
    const whereClause = {};
    if (matchId) {
      whereClause.matchId = matchId;
    }

    const flags = await Flag.findAll({
      where: whereClause,
      include: [
        { model: Match, as: 'match', attributes: ['id', 'name'] },
        { model: User, as: 'creator', attributes: ['id', 'username'] },
        { model: Team, as: 'capturingTeam', attributes: ['id', 'name', 'color'] },
        { model: User, as: 'capturingUser', attributes: ['id', 'username'] }
      ],
      order: [['createdAt', 'DESC']]
    });

    res.json({ flags });
  } catch (error) {
    console.error('Error in getAdminFlags:', error);
    res.status(500).json({ error: 'Failed to fetch flags' });
  }
};

/**
 * Update flag (admin only)
 */
exports.updateFlag = async (req, res) => {
  try {
    const { id } = req.params;
    const { name, description, flagValue, points, category, difficulty, hints, isActive } = req.body;

    const flag = await Flag.findByPk(id);
    if (!flag) {
      return res.status(404).json({ error: 'Flag not found' });
    }

    // Update flag with provided data
    const updateData = {};
    if (name !== undefined) updateData.name = name.trim();
    if (description !== undefined) updateData.description = description?.trim() || null;
    if (flagValue !== undefined) updateData.flagValue = flagValue.trim();
    if (points !== undefined) updateData.points = parseInt(points);
    if (category !== undefined) updateData.category = category;
    if (difficulty !== undefined) updateData.difficulty = difficulty;
    if (hints !== undefined) updateData.hints = hints;
    if (isActive !== undefined) updateData.isActive = isActive;

    await flag.update(updateData);

    // Fetch updated flag with associations
    const updatedFlag = await Flag.findByPk(id, {
      include: [
        { model: Match, as: 'match', attributes: ['id', 'name'] },
        { model: User, as: 'creator', attributes: ['id', 'username'] },
        { model: Team, as: 'capturingTeam', attributes: ['id', 'name', 'color'] },
        { model: User, as: 'capturingUser', attributes: ['id', 'username'] }
      ]
    });

    res.json({ 
      message: 'Flag updated successfully', 
      flag: updatedFlag 
    });
  } catch (error) {
    console.error('Error in updateFlag:', error);
    res.status(500).json({ error: 'Failed to update flag' });
  }
};

/**
 * Delete flag (admin only)
 */
exports.deleteFlag = async (req, res) => {
  try {
    const { id } = req.params;

    const flag = await Flag.findByPk(id);
    if (!flag) {
      return res.status(404).json({ error: 'Flag not found' });
    }

    // Check if flag has been captured
    if (flag.capturedBy) {
      return res.status(400).json({ 
        error: 'Cannot delete a flag that has been captured by a team' 
      });
    }

    await flag.destroy();

    res.json({ 
      message: 'Flag deleted successfully',
      deletedFlagId: id 
    });
  } catch (error) {
    console.error('Error in deleteFlag:', error);
    res.status(500).json({ error: 'Failed to delete flag' });
  }
};

/**
 * Update existing match (admin only)
 */
exports.updateMatch = async (req, res) => {
  try {
    const { id } = req.params;
    const { name, description, matchType, maxTeams, startTime, endTime, status, duration } = req.body;

    const match = await Match.findByPk(id);
    if (!match) {
      return res.status(404).json({ error: 'Match not found' });
    }

    // Update match with provided data
    const updateData = {};
    if (name !== undefined) updateData.name = name;
    if (description !== undefined) updateData.description = description;
    if (matchType !== undefined) updateData.matchType = matchType;
    if (maxTeams !== undefined) updateData.maxTeams = maxTeams;
    if (duration !== undefined) updateData.duration = duration * 60; // Convert minutes to seconds
    if (startTime !== undefined) {
      // Store the time as provided (treat as local time)
      updateData.startTime = startTime ? new Date(startTime) : null;
    }
    if (endTime !== undefined) {
      // Store the time as provided (treat as local time)
      updateData.endTime = endTime ? new Date(endTime) : null;
    }
    if (status !== undefined) updateData.status = status;

    await match.update(updateData);

    // Fetch updated match with creator details
    const updatedMatch = await Match.findByPk(id, {
      include: [
        { model: User, as: 'creator', attributes: ['id', 'username'] },
        { model: Team, as: 'teams', attributes: ['id', 'name', 'color', 'currentPoints'], through: { attributes: [] } }
      ]
    });

    res.json({ 
      message: 'Match updated successfully', 
      match: updatedMatch 
    });
  } catch (error) {
    console.error('Error in updateMatch:', error);
    res.status(500).json({ error: 'Failed to update match' });
  }
};

/**
 * Delete match (admin only)
 */
exports.deleteMatch = async (req, res) => {
  try {
    const { id } = req.params;
    const { ScoringEvent, Flag } = require('../models');

    const match = await Match.findByPk(id);
    if (!match) {
      return res.status(404).json({ error: 'Match not found' });
    }

    // Check if match is currently active
    if (match.status === 'active') {
      return res.status(400).json({ 
        error: 'Cannot delete an active match. Please stop the match first.' 
      });
    }

    // Delete related data using Sequelize methods
    // Delete scoring events
    await ScoringEvent.destroy({
      where: { matchId: id }
    });

    // Delete flags associated with this match
    await Flag.destroy({
      where: { matchId: id }
    });

    // Remove team associations (this will be handled by the through table)
    await match.setTeams([]);

    // Delete the match
    await match.destroy();

    res.json({ 
      message: 'Match deleted successfully',
      deletedMatchId: id 
    });
  } catch (error) {
    console.error('Error in deleteMatch:', error);
    res.status(500).json({ error: 'Failed to delete match' });
  }
};

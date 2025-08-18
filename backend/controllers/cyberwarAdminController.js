const { User, VM, Lab, Log } = require('../models');
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
      attributes: ['id', 'username', 'email', 'role', 'createdAt', 'updatedAt'],
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
    // For now, return dummy data until you implement the actual models
    const stats = {
      totalMatches: 0,
      activeMatches: 0,
      completedMatches: 0,
      totalTeams: 0,
      totalUsers: 0,
      totalFlags: 0,
      activeFlags: 0,
      capturedFlags: 0,
      totalVMs: 0,
      runningVMs: 0,
      stoppedVMs: 0,
      alerts: [
        {
          type: 'info',
          message: 'Cyberwar system is ready for competition'
        }
      ]
    };
    
    // You can add real data fetching here when you have the models:
    // const totalUsers = await User.count();
    // const totalVMs = await VM.count();
    // etc.
    
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

const { Team, User, Match, ScoringEvent, FlagSubmission, Challenge } = require('../models');
const { Op, Sequelize } = require('sequelize');
const logger = require('../config/logger');

/**
 * Get performance metrics over time
 * @route GET /api/analytics/performance
 * @param {string} range - Time range (day, week, month, year)
 */
exports.getPerformanceData = async (req, res) => {
  logger.info('getPerformanceData called', { userId: req.user?.id, query: req.query });
  try {
    const { range = 'month' } = req.query;
    const userId = req.user.id;
    
    // Calculate date range
    const now = new Date();
    let startDate = new Date();
    
    switch (range) {
      case 'day':
        startDate.setDate(now.getDate() - 1);
        break;
      case 'week':
        startDate.setDate(now.getDate() - 7);
        break;
      case 'year':
        startDate.setFullYear(now.getFullYear() - 1);
        break;
      case 'month':
      default:
        startDate.setMonth(now.getMonth() - 1);
    }

    // Get user's team
    const user = await User.findByPk(userId, {
      include: [{
        model: Team,
        as: 'teams',
        attributes: ['id'],
        through: { attributes: [] },
        required: true
      }]
    });

    if (!user || !user.teams || user.teams.length === 0) {
      return res.status(404).json({ 
        error: 'User is not part of any team' 
      });
    }

    const teamId = user.teams[0].id;

    // Get submissions for the team in the date range
    const submissions = await FlagSubmission.findAll({
      where: {
        teamId,
        createdAt: { [Op.gte]: startDate }
      },
      include: [
        {
          model: Challenge,
          attributes: ['points']
        }
      ],
      order: [['createdAt', 'ASC']]
    });

    // Group by time period (day, week, or month)
    const groupedData = {};
    const labels = [];
    const data = [];
    const averageData = [];

    // Generate labels based on range
    const period = range === 'day' ? 'hour' : 'day';
    const format = range === 'day' ? 'HH:00' : 'MMM D';
    
    // Initialize data points
    const current = new Date(startDate);
    while (current <= now) {
      const label = current.toLocaleString('en-US', { 
        hour: '2-digit',
        hour12: false,
        month: 'short',
        day: 'numeric'
      }).split(',').pop().trim();
      
      labels.push(label);
      data.push(0);
      averageData.push(0);
      
      if (range === 'day') {
        current.setHours(current.getHours() + 1);
      } else {
        current.setDate(current.getDate() + 1);
      }
    }

    // Process submissions
    submissions.forEach(submission => {
      const date = new Date(submission.createdAt);
      const label = date.toLocaleString('en-US', { 
        hour: '2-digit',
        hour12: false,
        month: 'short',
        day: 'numeric'
      }).split(',').pop().trim();
      
      const index = labels.indexOf(label);
      if (index !== -1) {
        data[index] += submission.Challenge ? submission.Challenge.points : 0;
      }
    });

    // Calculate average (mock data - in a real app, this would be calculated from all teams)
    const maxPoints = Math.max(...data, 1);
    averageData.forEach((_, i) => {
      averageData[i] = Math.round((maxPoints * 0.7) * (0.7 + Math.random() * 0.6));
    });

    res.json({
      labels,
      data,
      average: averageData
    });

  } catch (error) {
    logger.error('Error in getPerformanceData', { 
      error: error.message, 
      stack: error.stack,
      userId: req.user?.id 
    });
    res.status(500).json({ 
      error: 'Failed to fetch performance data',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
};

/**
 * Get category distribution
 * @route GET /api/analytics/categories
 */
exports.getCategoryData = async (req, res) => {
  logger.info('getCategoryData called', { userId: req.user?.id, query: req.query });
  try {
    const userId = req.user.id;
    
    // Get user's team
    const user = await User.findByPk(userId, {
      include: [{
        model: Team,
        as: 'teams',
        attributes: ['id'],
        through: { attributes: [] },
        required: true
      }]
    });

    if (!user || !user.teams || user.teams.length === 0) {
      return res.status(404).json({ 
        error: 'User is not part of any team' 
      });
    }

    const teamId = user.teams[0].id;

    // Get category distribution for the team
    const submissions = await FlagSubmission.findAll({
      where: { teamId },
      include: [
        {
          model: Challenge,
          attributes: ['category'],
          required: true
        }
      ]
    });

    // Count submissions by category
    const categoryCounts = {};
    submissions.forEach(sub => {
      const category = sub.Challenge.category || 'Other';
      categoryCounts[category] = (categoryCounts[category] || 0) + 1;
    });

    // Convert to arrays for chart
    const labels = Object.keys(categoryCounts);
    const data = Object.values(categoryCounts);

    res.json({ labels, data });

  } catch (error) {
    logger.error('Error in getCategoryData', { 
      error: error.message, 
      stack: error.stack,
      userId: req.user?.id 
    });
    res.status(500).json({ 
      error: 'Failed to fetch category data',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
};

/**
 * Get team statistics
 * @route GET /api/teams/stats
 */
exports.getTeamStats = async (req, res) => {
  logger.info('getTeamStats called', { userId: req.user?.id });
  try {
    const userId = req.user.id;
    
    // Get user's team
    const user = await User.findByPk(userId, {
      include: [{
        model: Team,
        as: 'teams',
        attributes: ['id', 'name', 'score'],
        through: { attributes: [] },
        required: true
      }]
    });

    if (!user || !user.teams || user.teams.length === 0) {
      return res.status(404).json({ 
        error: 'User is not part of any team' 
      });
    }

    const team = user.teams[0];

    // Get team rank (mock - in a real app, this would be calculated from all teams)
    const rank = Math.floor(Math.random() * 50) + 1;
    
    // Get total teams count
    const totalTeams = await Team.count();
    
    // Get top teams for comparison (excluding the user's team)
    const topTeams = await Team.findAll({
      attributes: ['id', 'name', 'score'],
      where: {
        id: { [Op.ne]: team.id }
      },
      order: [['score', 'DESC']],
      limit: 3
    });

    // Create comparison data
    const teams = [
      { name: team.name, score: team.score, isCurrentUser: true },
      ...topTeams.map(t => ({
        name: t.name,
        score: t.score,
        isCurrentUser: false
      }))
    ];

    res.json({
      teams,
      rank,
      totalTeams,
      percentile: Math.round(((totalTeams - rank) / totalTeams) * 100)
    });

  } catch (error) {
    logger.error('Error in getTeamStats', { 
      error: error.message, 
      stack: error.stack,
      userId: req.user?.id 
    });
    res.status(500).json({ 
      error: 'Failed to fetch team statistics',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
};

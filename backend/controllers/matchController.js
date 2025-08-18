const { Match, User, Team } = require('../models');
const { Op } = require('sequelize');

/**
 * Create a new match
 */
exports.createMatch = async (req, res) => {
  try {
    const { name, description, matchType, maxTeams, startTime, endTime, scoringConfig } = req.body;
    
    // Validate required fields
    if (!name || !matchType || !maxTeams || !startTime || !endTime) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    // Create the match
    const match = await Match.create({
      name,
      description,
      matchType,
      maxTeams,
      startTime: new Date(startTime),
      endTime: new Date(endTime),
      scoringConfig: scoringConfig || {
        flagCapture: 100,
        serviceUp: 10,
        serviceDown: -5,
        firstBlood: 50,
        slaViolation: -20
      },
      status: 'setup',
      createdBy: req.user.id
    });

    res.status(201).json(match);
  } catch (error) {
    console.error('Error creating match:', error);
    res.status(500).json({ error: 'Failed to create match', details: error.message });
  }
};

/**
 * Get all matches
 */
exports.getMatches = async (req, res) => {
  try {
    const { status, page = 1, limit = 10 } = req.query;
    const offset = (page - 1) * limit;

    const whereClause = {};
    if (status) {
      whereClause.status = status;
    }

    const { count, rows: matches } = await Match.findAndCountAll({
      where: whereClause,
      limit: parseInt(limit),
      offset: parseInt(offset),
      order: [['createdAt', 'DESC']],
      include: [
        {
          model: User,
          as: 'creator',
          attributes: ['id', 'username', 'email']
        }
      ]
    });

    res.json({
      matches,
      pagination: {
        total: count,
        page: parseInt(page),
        pages: Math.ceil(count / limit),
        limit: parseInt(limit)
      }
    });
  } catch (error) {
    console.error('Error fetching matches:', error);
    res.status(500).json({ error: 'Failed to fetch matches' });
  }
};

/**
 * Get match by ID
 */
exports.getMatchById = async (req, res) => {
  try {
    const { id } = req.params;
    const match = await Match.findByPk(id, {
      include: [
        {
          model: User,
          as: 'creator',
          attributes: ['id', 'username', 'email']
        },
        {
          model: Team,
          as: 'teams',
          attributes: ['id', 'name', 'score']
        }
      ]
    });

    if (!match) {
      return res.status(404).json({ error: 'Match not found' });
    }

    res.json(match);
  } catch (error) {
    console.error('Error fetching match:', error);
    res.status(500).json({ error: 'Failed to fetch match' });
  }
};

/**
 * Update match
 */
exports.updateMatch = async (req, res) => {
  try {
    const { id } = req.params;
    const updates = req.body;

    // Don't allow updating certain fields directly
    delete updates.status;
    delete updates.createdBy;
    delete updates.currentTeams;

    const [updated] = await Match.update(updates, {
      where: { id },
      returning: true
    });

    if (!updated) {
      return res.status(404).json({ error: 'Match not found' });
    }

    const match = await Match.findByPk(id);
    res.json(match);
  } catch (error) {
    console.error('Error updating match:', error);
    res.status(500).json({ error: 'Failed to update match' });
  }
};

/**
 * Delete match
 */
exports.deleteMatch = async (req, res) => {
  try {
    const { id } = req.params;
    
    const deleted = await Match.destroy({
      where: { id }
    });

    if (!deleted) {
      return res.status(404).json({ error: 'Match not found' });
    }

    res.json({ message: 'Match deleted successfully' });
  } catch (error) {
    console.error('Error deleting match:', error);
    res.status(500).json({ error: 'Failed to delete match' });
  }
};

/**
 * Start a match
 */
exports.startMatch = async (req, res) => {
  try {
    const { id } = req.params;
    
    const match = await Match.findByPk(id);
    if (!match) {
      return res.status(404).json({ error: 'Match not found' });
    }

    if (match.status !== 'setup') {
      return res.status(400).json({ error: 'Match is not in setup status' });
    }

    match.status = 'waiting';
    await match.save();

    // TODO: Add logic to prepare VMs, networks, etc.

    res.json({ message: 'Match started successfully', match });
  } catch (error) {
    console.error('Error starting match:', error);
    res.status(500).json({ error: 'Failed to start match' });
  }
};

/**
 * End a match
 */
exports.endMatch = async (req, res) => {
  try {
    const { id } = req.params;
    const { reason = 'admin_ended' } = req.body;
    
    const match = await Match.findByPk(id);
    if (!match) {
      return res.status(404).json({ error: 'Match not found' });
    }

    if (match.status === 'finished' || match.status === 'cancelled') {
      return res.status(400).json({ error: 'Match is already ended' });
    }

    match.status = 'finished';
    match.endReason = reason;
    match.endedAt = new Date();
    await match.save();

    // TODO: Add cleanup logic (stop VMs, release resources, etc.)

    res.json({ message: 'Match ended successfully', match });
  } catch (error) {
    console.error('Error ending match:', error);
    res.status(500).json({ error: 'Failed to end match' });
  }
};

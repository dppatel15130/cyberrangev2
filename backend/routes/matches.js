const express = require('express');
const { Match, Team, User, ScoringEvent } = require('../models');
const { auth: authenticateToken, admin: requireAdmin } = require('../middleware/auth');
const gameEngine = require('../services/gameEngine');
const scoringService = require('../services/scoringService');
const router = express.Router();

// Get all matches with optional filtering
router.get('/', authenticateToken, async (req, res) => {
  try {
    const { status, type, page = 1, limit = 20 } = req.query;
    const offset = (page - 1) * limit;
    
    const where = {};
    if (status) where.status = status;
    if (type) where.matchType = type;

    const matches = await Match.findAndCountAll({
      where,
      include: [
        {
          model: Team,
          as: 'teams',
          attributes: ['id', 'name', 'color', 'currentPoints', 'totalFlags'],
          through: { attributes: [] }
        },
        {
          model: User,
          as: 'creator',
          attributes: ['id', 'username', 'role']
        }
      ],
      order: [['createdAt', 'DESC']],
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
    console.error('Error fetching matches:', error);
    res.status(500).json({ error: 'Failed to fetch matches' });
  }
});

// Get active matches for real-time dashboard
router.get('/active', authenticateToken, async (req, res) => {
  try {
    const activeMatches = await Match.findAll({
      where: { status: 'active' },
      include: [
        {
          model: Team,
          as: 'teams',
          attributes: ['id', 'name', 'color', 'currentPoints', 'lastActivity'],
          through: { attributes: [] },
          include: [
            {
              model: ScoringEvent,
              as: 'scoringEvents',
              attributes: ['eventType', 'finalPoints', 'createdAt'],
              limit: 5,
              order: [['createdAt', 'DESC']]
            }
          ]
        }
      ],
      order: [['startTime', 'ASC']]
    });

    // Add real-time statistics for each match
    const matchesWithStats = await Promise.all(
      activeMatches.map(async (match) => {
        const statistics = await scoringService.getMatchStatistics(match.id);
        return {
          ...match.toJSON(),
          statistics,
          duration: match.startTime ? Date.now() - match.startTime.getTime() : 0
        };
      })
    );

    res.json(matchesWithStats);
  } catch (error) {
    console.error('Error fetching active matches:', error);
    res.status(500).json({ error: 'Failed to fetch active matches' });
  }
});

// Get specific match details
router.get('/:id', authenticateToken, async (req, res) => {
  try {
    const match = await Match.findByPk(req.params.id, {
      include: [
        {
          model: Team,
          as: 'teams',
          through: { attributes: [] },
          include: [
            {
              model: User,
              as: 'members',
              attributes: ['id', 'username', 'role'],
              through: { attributes: ['joinedAt'] }
            },
            {
              model: ScoringEvent,
              as: 'scoringEvents',
              where: { matchId: req.params.id },
              required: false,
              order: [['createdAt', 'DESC']],
              limit: 20
            }
          ]
        },
        {
          model: User,
          as: 'creator',
          attributes: ['id', 'username', 'role']
        }
      ]
    });

    if (!match) {
      return res.status(404).json({ error: 'Match not found' });
    }

    // Add match statistics if active
    let statistics = null;
    if (match.status === 'active') {
      statistics = await scoringService.getMatchStatistics(match.id);
    }

    res.json({
      ...match.toJSON(),
      statistics
    });
  } catch (error) {
    console.error('Error fetching match:', error);
    res.status(500).json({ error: 'Failed to fetch match details' });
  }
});

// Create new match (admin only)
router.post('/', authenticateToken, requireAdmin, async (req, res) => {
  try {
    console.log('Received match creation request:', JSON.stringify(req.body, null, 2));
    
    const {
      name,
      description,
      matchType,
      duration,
      maxTeams,
      autoScoring = true,
      packetCaptureEnabled = true,
      logAnalysisEnabled = false,
      elkIntegration = false,
      networkConfig = null,
      vmConfig = null,
      scoringRules = null,
      flags = []
    } = req.body;

    // Validate required fields
    if (!name || !matchType) {
      console.error('Validation failed: Missing required fields', { name, matchType });
      return res.status(400).json({ 
        error: 'Match name and type are required',
        details: { name: !!name, matchType: !!matchType }
      });
    }

    // Validate match type
    const validMatchTypes = ['attack_defend', 'capture_flag', 'red_vs_blue', 'free_for_all'];
    if (!validMatchTypes.includes(matchType)) {
      console.error('Validation failed: Invalid match type', { matchType });
      return res.status(400).json({ 
        error: 'Invalid match type',
        validTypes: validMatchTypes
      });
    }

    // Prepare match data
    const matchData = {
      name: name.trim(),
      description: (description || '').trim(),
      matchType,
      duration: duration ? parseInt(duration, 10) : 7200, // Default to 2 hours in seconds
      maxTeams: maxTeams ? parseInt(maxTeams, 10) : 4,
      autoScoring,
      packetCaptureEnabled,
      logAnalysisEnabled,
      elkIntegration,
      networkConfig,
      vmConfig,
      scoringRules,
      flags
    };

    console.log('Creating match with data:', JSON.stringify(matchData, null, 2));
    
    const match = await gameEngine.createMatch(matchData, req.user.id);
    
    console.log('Successfully created match:', match.id);
    res.status(201).json(match);
  } catch (error) {
    console.error('Error in match creation:', {
      error: error.message,
      stack: error.stack,
      requestBody: req.body
    });
    
    // Handle specific error types
    if (error.name === 'SequelizeValidationError' || error.name === 'SequelizeUniqueConstraintError') {
      const errors = error.errors.map(err => ({
        field: err.path,
        message: err.message,
        value: err.value
      }));
      return res.status(400).json({ 
        error: 'Validation error',
        details: errors 
      });
    }
    
    res.status(500).json({ 
      error: 'Failed to create match',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Update match (admin only)
router.put('/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const match = await Match.findByPk(req.params.id);
    if (!match) {
      return res.status(404).json({ error: 'Match not found' });
    }

    // Don't allow updates to active matches
    if (match.status === 'active') {
      return res.status(400).json({ error: 'Cannot update active match' });
    }

    const allowedUpdates = [
      'name', 'description', 'duration', 'maxTeams', 'teamsPerMatch',
      'autoScoring', 'packetCaptureEnabled', 'logAnalysisEnabled',
      'elkIntegration', 'networkConfig', 'vmConfig', 'scoringRules', 'flags'
    ];

    const updates = {};
    allowedUpdates.forEach(field => {
      if (req.body[field] !== undefined) {
        updates[field] = req.body[field];
      }
    });

    await match.update(updates);
    
    const updatedMatch = await Match.findByPk(req.params.id, {
      include: [
        { model: Team, as: 'teams', through: { attributes: [] } },
        { model: User, as: 'creator', attributes: ['id', 'username'] }
      ]
    });

    res.json(updatedMatch);
  } catch (error) {
    console.error('Error updating match:', error);
    res.status(500).json({ error: 'Failed to update match' });
  }
});

// Add teams to match
router.post('/:id/teams', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { teamIds } = req.body;
    
    if (!Array.isArray(teamIds) || teamIds.length === 0) {
      return res.status(400).json({ error: 'Team IDs array is required' });
    }

    const match = await Match.findByPk(req.params.id);
    if (!match) {
      return res.status(404).json({ error: 'Match not found' });
    }

    if (match.status !== 'created') {
      return res.status(400).json({ error: 'Cannot modify teams of non-created match' });
    }

    // Verify teams exist
    const teams = await Team.findAll({
      where: { id: teamIds }
    });

    if (teams.length !== teamIds.length) {
      return res.status(404).json({ error: 'One or more teams not found' });
    }

    // Check team limits
    const currentTeamCount = await match.countTeams();
    if (currentTeamCount + teams.length > match.maxTeams) {
      return res.status(400).json({ 
        error: `Adding these teams would exceed the maximum limit of ${match.maxTeams} teams` 
      });
    }

    // Add teams to match
    await match.addTeams(teams);

    // If we have enough teams, set match to ready
    const newTeamCount = currentTeamCount + teams.length;
    if (newTeamCount >= match.teamsPerMatch && match.status === 'created') {
      match.status = 'ready';
      await match.save();
    }

    const updatedMatch = await Match.findByPk(req.params.id, {
      include: [{ model: Team, as: 'teams', through: { attributes: [] } }]
    });

    res.json({
      message: `Added ${teams.length} teams to match`,
      match: updatedMatch
    });
  } catch (error) {
    console.error('Error adding teams to match:', error);
    res.status(500).json({ error: 'Failed to add teams to match' });
  }
});

// Remove teams from match
router.delete('/:id/teams', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { teamIds } = req.body;
    
    if (!Array.isArray(teamIds) || teamIds.length === 0) {
      return res.status(400).json({ error: 'Team IDs array is required' });
    }

    const match = await Match.findByPk(req.params.id);
    if (!match) {
      return res.status(404).json({ error: 'Match not found' });
    }

    if (match.status === 'active') {
      return res.status(400).json({ error: 'Cannot remove teams from active match' });
    }

    // Remove teams from match
    await match.removeTeams(teamIds);

    // Check if match should be set back to created status
    const remainingTeamCount = await match.countTeams();
    if (remainingTeamCount < match.teamsPerMatch && match.status === 'ready') {
      match.status = 'created';
      await match.save();
    }

    const updatedMatch = await Match.findByPk(req.params.id, {
      include: [{ model: Team, as: 'teams', through: { attributes: [] } }]
    });

    res.json({
      message: `Removed ${teamIds.length} teams from match`,
      match: updatedMatch
    });
  } catch (error) {
    console.error('Error removing teams from match:', error);
    res.status(500).json({ error: 'Failed to remove teams from match' });
  }
});

// Start match (admin only)
router.post('/:id/start', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const match = await Match.findByPk(req.params.id, {
      include: [{ model: Team, as: 'teams' }]
    });

    if (!match) {
      return res.status(404).json({ error: 'Match not found' });
    }

    if (match.status !== 'ready') {
      return res.status(400).json({ 
        error: `Match is not ready to start. Current status: ${match.status}` 
      });
    }

    // Start the match using game engine
    await gameEngine.startMatch(match.id, req.user.id);

    res.json({
      message: 'Match started successfully',
      matchId: match.id,
      startTime: new Date()
    });
  } catch (error) {
    console.error('Error starting match:', error);
    res.status(500).json({ 
      error: 'Failed to start match: ' + error.message 
    });
  }
});

// End match (admin only)
router.post('/:id/end', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { reason = 'admin_ended' } = req.body;
    
    const match = await Match.findByPk(req.params.id);
    if (!match) {
      return res.status(404).json({ error: 'Match not found' });
    }

    if (match.status !== 'active') {
      return res.status(400).json({ error: 'Match is not active' });
    }

    // End the match using game engine
    const finalResults = await gameEngine.endMatch(match.id, req.user.id, reason);

    res.json({
      message: 'Match ended successfully',
      matchId: match.id,
      endTime: new Date(),
      finalResults
    });
  } catch (error) {
    console.error('Error ending match:', error);
    res.status(500).json({ 
      error: 'Failed to end match: ' + error.message 
    });
  }
});

// Get match scoreboard
router.get('/:id/scoreboard', authenticateToken, async (req, res) => {
  try {
    const match = await Match.findByPk(req.params.id, {
      include: [
        {
          model: Team,
          as: 'teams',
          through: { attributes: [] },
          include: [
            {
              model: ScoringEvent,
              as: 'scoringEvents',
              where: { matchId: req.params.id, isActive: true },
              required: false,
              attributes: ['eventType', 'finalPoints', 'createdAt'],
              order: [['createdAt', 'DESC']],
              limit: 10
            }
          ]
        }
      ]
    });

    if (!match) {
      return res.status(404).json({ error: 'Match not found' });
    }

    const scoreboard = match.teams
      .map(team => ({
        teamId: team.id,
        teamName: team.name,
        teamColor: team.color,
        currentPoints: team.currentPoints,
        totalFlags: team.totalFlags,
        lastActivity: team.lastActivity,
        recentEvents: team.scoringEvents.map(event => ({
          type: event.eventType,
          points: event.finalPoints,
          time: event.createdAt
        })),
        eventCounts: team.scoringEvents.reduce((counts, event) => {
          counts[event.eventType] = (counts[event.eventType] || 0) + 1;
          return counts;
        }, {})
      }))
      .sort((a, b) => b.currentPoints - a.currentPoints)
      .map((team, index) => ({
        ...team,
        rank: index + 1
      }));

    // Calculate match statistics
    const totalEvents = scoreboard.reduce((sum, team) => sum + team.recentEvents.length, 0);
    const totalPoints = scoreboard.reduce((sum, team) => sum + team.currentPoints, 0);
    
    res.json({
      matchId: match.id,
      matchName: match.name,
      status: match.status,
      startTime: match.startTime,
      duration: match.startTime ? Date.now() - match.startTime.getTime() : 0,
      scoreboard,
      statistics: {
        totalTeams: scoreboard.length,
        totalEvents,
        totalPoints,
        averagePointsPerTeam: totalPoints / scoreboard.length || 0,
        lastUpdate: new Date()
      }
    });
  } catch (error) {
    console.error('Error fetching match scoreboard:', error);
    res.status(500).json({ error: 'Failed to fetch match scoreboard' });
  }
});

// Get match events/timeline
router.get('/:id/events', authenticateToken, async (req, res) => {
  try {
    const { page = 1, limit = 50, eventType, teamId } = req.query;
    const offset = (page - 1) * limit;
    
    const where = { matchId: req.params.id, isActive: true };
    if (eventType) where.eventType = eventType;
    if (teamId) where.teamId = teamId;

    const events = await ScoringEvent.findAndCountAll({
      where,
      include: [
        {
          model: Team,
          as: 'team',
          attributes: ['id', 'name', 'color']
        },
        {
          model: User,
          as: 'user',
          attributes: ['id', 'username'],
          required: false
        }
      ],
      order: [['createdAt', 'DESC']],
      limit: parseInt(limit),
      offset: parseInt(offset)
    });

    res.json({
      events: events.rows.map(event => ({
        id: event.id,
        type: event.eventType,
        subtype: event.eventSubtype,
        description: event.description,
        points: event.finalPoints,
        confidence: event.confidence,
        team: event.team,
        user: event.user?.username,
        sourceType: event.sourceType,
        timestamp: event.createdAt,
        evidence: event.evidence ? Object.keys(event.evidence).length : 0
      })),
      pagination: {
        total: events.count,
        pages: Math.ceil(events.count / limit),
        currentPage: parseInt(page),
        hasNext: offset + limit < events.count,
        hasPrev: page > 1
      }
    });
  } catch (error) {
    console.error('Error fetching match events:', error);
    res.status(500).json({ error: 'Failed to fetch match events' });
  }
});

// Manual scoring by admin
router.post('/:id/score', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const {
      teamId,
      eventType,
      points,
      description,
      evidence
    } = req.body;

    if (!teamId || !eventType || points === undefined || !description) {
      return res.status(400).json({ 
        error: 'Team ID, event type, points, and description are required' 
      });
    }

    const match = await Match.findByPk(req.params.id);
    if (!match) {
      return res.status(404).json({ error: 'Match not found' });
    }

    if (match.status !== 'active') {
      return res.status(400).json({ error: 'Match is not active' });
    }

    // Verify team is in this match
    const teamInMatch = await match.hasTeam(teamId);
    if (!teamInMatch) {
      return res.status(400).json({ error: 'Team is not participating in this match' });
    }

    // Create manual scoring event
    const scoringEvent = await scoringService.createScoringEvent(match.id, teamId, {
      eventType,
      points,
      finalPoints: points,
      description,
      confidence: 1.0, // Manual scores have full confidence
      sourceType: 'manual_admin',
      userId: req.user.id,
      evidence: evidence || { manual: true, admin: req.user.username },
      isActive: true
    });

    res.json({
      message: 'Manual score added successfully',
      event: scoringEvent
    });
  } catch (error) {
    console.error('Error adding manual score:', error);
    res.status(500).json({ error: 'Failed to add manual score' });
  }
});

// Get match configuration templates
router.get('/templates/config', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const templates = {
      networkConfigs: [
        {
          name: 'Isolated Teams',
          description: 'Teams cannot communicate with each other',
          config: {
            isolation: true,
            allowInterTeamCommunication: false,
            allowInternetAccess: false,
            networkSegmentation: true,
            monitorTraffic: true
          }
        },
        {
          name: 'Open Network',
          description: 'Teams can attack each other freely',
          config: {
            isolation: false,
            allowInterTeamCommunication: true,
            allowInternetAccess: false,
            networkSegmentation: false,
            monitorTraffic: true
          }
        }
      ],
      vmConfigs: [
        {
          name: 'Basic Attack/Defense',
          description: 'One attacker VM and one target VM per team',
          config: {
            templates: [
              { templateId: 9001, name: 'Ubuntu-Target', role: 'target' },
              { templateId: 9003, name: 'Kali-Attacker', role: 'attacker' }
            ],
            autoStart: true,
            resourceLimits: { cpu: 2, memory: 2048, disk: 20 }
          }
        },
        {
          name: 'Enterprise Environment',
          description: 'Multiple targets including Windows and web servers',
          config: {
            templates: [
              { templateId: 9001, name: 'Ubuntu-Target', role: 'target' },
              { templateId: 9002, name: 'Windows-Target', role: 'target' },
              { templateId: 9004, name: 'DVWA-Server', role: 'server' },
              { templateId: 9003, name: 'Kali-Attacker', role: 'attacker' }
            ],
            autoStart: true,
            resourceLimits: { cpu: 4, memory: 4096, disk: 40 }
          }
        }
      ],
      scoringRules: [
        {
          name: 'Standard Competition',
          description: 'Balanced scoring for various attack types',
          rules: {
            autoScoring: true,
            confidenceThreshold: 0.7,
            pointValues: {
              'network_compromise': 25,
              'vulnerability_exploit': 30,
              'attack_success': 50,
              'lateral_movement': 35,
              'flag_capture': 100
            },
            penaltyRules: {
              'detection_evasion': -10,
              'service_disruption': -25
            }
          }
        }
      ]
    };

    res.json(templates);
  } catch (error) {
    console.error('Error fetching configuration templates:', error);
    res.status(500).json({ error: 'Failed to fetch configuration templates' });
  }
});

// Delete match (admin only, only if not active)
router.delete('/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const match = await Match.findByPk(req.params.id);
    if (!match) {
      return res.status(404).json({ error: 'Match not found' });
    }

    if (match.status === 'active') {
      return res.status(400).json({ error: 'Cannot delete active match' });
    }

    // Remove team associations first
    await match.setTeams([]);

    // Delete all scoring events
    await ScoringEvent.destroy({ where: { matchId: match.id } });

    // Delete the match
    await match.destroy();

    res.json({ message: 'Match deleted successfully' });
  } catch (error) {
    console.error('Error deleting match:', error);
    res.status(500).json({ error: 'Failed to delete match' });
  }
});

module.exports = router;

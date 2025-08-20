const express = require('express');
const { Match, Team, User, ScoringEvent, Flag } = require('../models');
const { auth: authenticateToken, admin: requireAdmin } = require('../middleware/auth');
const gameEngine = require('../services/gameEngine');
const scoringService = require('../services/scoringService');
const guacamoleService = require('../services/guacamoleService');
const vmAssignmentService = require('../services/vmAssignmentService');
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
              through: { attributes: [] }
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

// Leave a match
router.post('/:id/leave', authenticateToken, async (req, res) => {
  try {
    const match = await Match.findByPk(req.params.id);
    if (!match) {
      return res.status(404).json({ error: 'Match not found' });
    }

    if (match.status === 'active') {
      return res.status(400).json({ error: 'Cannot leave an active match' });
    }

    // Get user's team for this match
    const userTeam = await match.getTeams({
      include: [
        {
          model: User,
          as: 'members',
          where: { id: req.user.id },
          attributes: ['id']
        }
      ]
    });

    if (userTeam.length === 0) {
      return res.status(403).json({ error: 'You are not participating in this match' });
    }

    const team = userTeam[0];

    // Remove team from match
    await match.removeTeam(team);
    
    // Update current teams count
    const currentTeamCount = await match.countTeams();
    await match.update({ currentTeams: currentTeamCount });

    // Update match status if needed
    if (match.status === 'waiting' && currentTeamCount < 2) {
      await match.update({ status: 'setup' });
    }

    res.json({
      message: 'Successfully left match',
      match: await Match.findByPk(match.id, {
        include: [
          {
            model: Team,
            as: 'teams',
            through: { attributes: [] }
          }
        ]
      })
    });
  } catch (error) {
    console.error('Error leaving match:', error);
    res.status(500).json({ error: 'Failed to leave match' });
  }
});

// Join a match with a team
router.post('/:id/join', authenticateToken, async (req, res) => {
  try {
    const { teamId } = req.body;
    
    if (!teamId) {
      return res.status(400).json({ error: 'Team ID is required' });
    }

    const match = await Match.findByPk(req.params.id);
    if (!match) {
      return res.status(404).json({ error: 'Match not found' });
    }

    if (match.status !== 'waiting' && match.status !== 'setup') {
      return res.status(400).json({ error: 'Match is not accepting new teams' });
    }

    // Check if team exists and user is a member
    const team = await Team.findByPk(teamId, {
      include: [
        {
          model: User,
          as: 'members',
          where: { id: req.user.id },
          attributes: ['id']
        }
      ]
    });

    if (!team) {
      return res.status(404).json({ error: 'Team not found' });
    }

    if (team.members.length === 0) {
      return res.status(403).json({ error: 'You are not a member of this team' });
    }

    // Check if team is already in the match
    const isAlreadyInMatch = await match.hasTeam(teamId);
    if (isAlreadyInMatch) {
      return res.status(400).json({ error: 'Team is already participating in this match' });
    }

    // Check if match has capacity
    const currentTeamCount = await match.countTeams();
    if (currentTeamCount >= match.maxTeams) {
      return res.status(400).json({ error: 'Match is at maximum capacity' });
    }

    // Add team to match
    await match.addTeam(team);
    
    // Update match status if needed
    if (match.status === 'setup' && currentTeamCount + 1 >= 2) {
      await match.update({ status: 'waiting' });
    }

    // Update current teams count
    await match.update({ currentTeams: currentTeamCount + 1 });

    // Setup Guacamole access for team members
    try {
      console.log(`Setting up Guacamole access for team ${team.name} (ID: ${team.id})`);
      const guacamoleResult = await guacamoleService.setupTeamAccess(team.id);
      
      if (guacamoleResult.success) {
        console.log(`✅ Guacamole access configured for team ${team.name}`);
        console.log('Results:', guacamoleResult.results);
      } else {
        console.warn(`⚠️  Failed to setup Guacamole access for team ${team.name}:`, guacamoleResult.error);
      }
    } catch (guacamoleError) {
      console.error(`❌ Error setting up Guacamole access:`, guacamoleError);
      // Don't fail the join process if Guacamole setup fails
    }

    // Assign VMs to team members
    try {
      console.log(`Assigning VMs to team ${team.name} (ID: ${team.id})`);
      const vmResult = await vmAssignmentService.assignVMsToTeam(team.id, match.id);
      
      if (vmResult.success) {
        console.log(`✅ VMs assigned to team ${team.name}`);
        console.log('Assigned VMs:', vmResult.assignedVMs);
      } else {
        console.warn(`⚠️  Failed to assign VMs to team ${team.name}:`, vmResult.error);
      }
    } catch (vmError) {
      console.error(`❌ Error assigning VMs:`, vmError);
      // Don't fail the join process if VM assignment fails
    }

    res.json({
      message: 'Successfully joined match',
      match: await Match.findByPk(match.id, {
        include: [
          {
            model: Team,
            as: 'teams',
            through: { attributes: [] }
          }
        ]
      })
    });
  } catch (error) {
    console.error('Error joining match:', error);
    res.status(500).json({ error: 'Failed to join match' });
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

    if (match.status !== 'waiting') {
      return res.status(400).json({ 
        error: `Match is not ready to start. Current status: ${match.status}` 
      });
    }

    // Initialize VM assignment service
    try {
      await vmAssignmentService.initializeVMPool();
      console.log(`✅ VM assignment service initialized for match ${match.id}`);
    } catch (vmError) {
      console.warn(`⚠️  VM assignment service error:`, vmError.message);
    }

    // Assign VMs to all teams in the match
    try {
      const teams = await match.getTeams();
      for (const team of teams) {
        const vmResult = await vmAssignmentService.assignVMsToTeam(team.id, match.id);
        if (vmResult.success) {
          console.log(`✅ VMs assigned to team ${team.name} for active match`);
        } else {
          console.warn(`⚠️  Failed to assign VMs to team ${team.name}:`, vmResult.error);
        }
      }
    } catch (vmError) {
      console.warn(`⚠️  Error assigning VMs for active match:`, vmError.message);
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

// Pause match (admin only)
router.post('/:id/pause', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const match = await Match.findByPk(req.params.id);
    if (!match) {
      return res.status(404).json({ error: 'Match not found' });
    }

    if (match.status !== 'active') {
      return res.status(400).json({ 
        error: `Match is not active. Current status: ${match.status}` 
      });
    }

    // Update match status to paused
    await match.update({ status: 'paused' });

    res.json({
      message: 'Match paused successfully',
      matchId: match.id,
      pauseTime: new Date()
    });
  } catch (error) {
    console.error('Error pausing match:', error);
    res.status(500).json({ 
      error: 'Failed to pause match: ' + error.message 
    });
  }
});

// Resume match (admin only)
router.post('/:id/resume', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const match = await Match.findByPk(req.params.id);
    if (!match) {
      return res.status(404).json({ error: 'Match not found' });
    }

    if (match.status !== 'paused') {
      return res.status(400).json({ 
        error: `Match is not paused. Current status: ${match.status}` 
      });
    }

    // Update match status back to active
    await match.update({ status: 'active' });

    res.json({
      message: 'Match resumed successfully',
      matchId: match.id,
      resumeTime: new Date()
    });
  } catch (error) {
    console.error('Error resuming match:', error);
    res.status(500).json({ 
      error: 'Failed to resume match: ' + error.message 
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

// Get user's team for a specific match
router.get('/:id/user-team', authenticateToken, async (req, res) => {
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
              where: { id: req.user.id },
              attributes: ['id'],
              through: { attributes: [] }
            }
          ]
        }
      ]
    });

    if (!match) {
      return res.status(404).json({ error: 'Match not found' });
    }

    // Find the team that the user is a member of in this match
    const userTeam = match.teams.find(team => team.members.length > 0);
    
    if (!userTeam) {
      return res.status(404).json({ error: 'User is not in any team for this match' });
    }

    res.json(userTeam);
  } catch (error) {
    console.error('Error fetching user team for match:', error);
    res.status(500).json({ error: 'Failed to fetch user team for match' });
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

// Submit flag for match
router.post('/:id/flags/submit', authenticateToken, async (req, res) => {
  try {
    const { flagId, value } = req.body;
    
    if (!flagId || !value) {
      return res.status(400).json({ error: 'Flag ID and value are required' });
    }

    const match = await Match.findByPk(req.params.id);
    if (!match) {
      return res.status(404).json({ error: 'Match not found' });
    }

    if (match.status !== 'active') {
      return res.status(400).json({ error: 'Match is not active' });
    }

    // Get user's team for this match
    const userTeam = await match.getTeams({
      include: [
        {
          model: User,
          as: 'members',
          where: { id: req.user.id },
          attributes: ['id']
        }
      ]
    });

    if (userTeam.length === 0) {
      return res.status(403).json({ error: 'You are not participating in this match' });
    }

    const team = userTeam[0];

    // Define cyber-warfare flags and their point values based on flag challenge IDs
    const challengeFlags = {
      // Basic challenges
      'basic_flag_1': {
        flags: ['CYBERWAR{basic_challenge_complete}', 'cyberwar{hello_world}'],
        points: 50,
        type: 'flag_capture'
      },
      'intermediate_flag_1': {
        flags: ['CYBERWAR{intermediate_puzzle_solved}', 'cyberwar{security_basics}'],
        points: 100,
        type: 'flag_capture'
      },

      // Web challenges
      'web_vuln_1': {
        flags: ['CYBERWAR{web_shell_upload}', 'CYBERWAR{sql_injection}', 'cyberwar{xss_exploit}'],
        points: 100,
        type: 'vulnerability_exploit'
      },

      // Network challenges
      'network_recon_1': {
        flags: ['CYBERWAR{network_discovery}', 'CYBERWAR{port_scan_complete}', 'CYBERWAR{service_enumeration}'],
        points: 150,
        type: 'network_compromise'
      },

      // System challenges
      'privilege_esc_1': {
        flags: ['CYBERWAR{privilege_escalation}', 'CYBERWAR{system_access}', 'CYBERWAR{admin_credentials}'],
        points: 200,
        type: 'attack_success'
      },

      // Data challenges
      'data_exfil_1': {
        flags: ['CYBERWAR{sensitive_data_found}', 'CYBERWAR{database_compromised}', 'CYBERWAR{data_exfiltration}'],
        points: 250,
        type: 'lateral_movement'
      }
    };

    const challengeData = challengeFlags[flagId];
    if (!challengeData) {
      return res.status(400).json({ 
        error: 'Invalid flag challenge ID',
        success: false 
      });
    }

    // Check if flag value matches any of the accepted flags for this challenge
    const submittedFlag = value.trim();
    const isCorrect = challengeData.flags.some(acceptedFlag => 
      acceptedFlag.toLowerCase() === submittedFlag.toLowerCase()
    );

    if (!isCorrect) {
      return res.json({
        success: false,
        correct: false,
        message: 'Incorrect flag value. Keep trying!',
        points: 0
      });
    }

    // Check for duplicate submission
    const existingSubmission = await ScoringEvent.findOne({
      where: {
        matchId: req.params.id,
        teamId: team.id,
        challengeId: flagId,
        eventType: challengeData.type,
        isActive: true
      }
    });

    if (existingSubmission) {
      return res.status(409).json({
        success: false,
        message: 'Your team has already captured this flag',
        alreadyCaptured: true
      });
    }

    // Create scoring event for correct flag submission
    const scoringEvent = await ScoringEvent.create({
      matchId: req.params.id,
      teamId: team.id,
      userId: req.user.id,
      eventType: challengeData.type,
      eventSubtype: 'flag_submission',
      challengeId: flagId,
      challengeName: flagId.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase()),
      basePoints: challengeData.points,
      multiplier: 1.0,
      finalPoints: challengeData.points,
      eventDetails: {
        flagId,
        submittedFlag: submittedFlag,
        challengeType: challengeData.type,
        difficulty: flagId.includes('basic') ? 'beginner' : 
                   flagId.includes('intermediate') ? 'intermediate' : 'advanced'
      },
      timestamp: new Date(),
      isActive: true
    });

    // Update team score
    const currentPoints = await ScoringEvent.sum('finalPoints', {
      where: {
        matchId: req.params.id,
        teamId: team.id,
        isActive: true
      }
    });

    await team.update({ currentPoints: currentPoints || 0 });

    res.json({
      success: true,
      correct: true,
      message: `Correct flag! +${challengeData.points} points awarded to ${team.name}`,
      points: challengeData.points,
      totalPoints: currentPoints || 0,
      flagId,
      teamId: team.id
    });

  } catch (error) {
    console.error('Error submitting flag:', error);
    res.status(500).json({ error: 'Failed to submit flag' });
  }
});

// Get match flags
router.get('/:id/flags', authenticateToken, async (req, res) => {
  try {
    const match = await Match.findByPk(req.params.id, {
      include: [
        {
          model: Flag,
          as: 'matchFlags',
          where: { isActive: true },
          required: false,
          include: [
            {
              model: Team,
              as: 'capturingTeam',
              attributes: ['id', 'name', 'color']
            },
            {
              model: User,
              as: 'capturingUser',
              attributes: ['id', 'username']
            }
          ]
        }
      ]
    });

    if (!match) {
      return res.status(404).json({ error: 'Match not found' });
    }

    // Format flags for frontend
    const flags = match.matchFlags.map(flag => ({
      id: flag.id,
      name: flag.name,
      description: flag.description,
      category: flag.category,
      points: flag.points,
      difficulty: flag.difficulty,
      hints: flag.hints || [],
      captured: !!flag.capturedBy,
      captureInfo: flag.capturedBy ? {
        teamId: flag.capturedBy,
        teamName: flag.capturingTeam?.name,
        teamColor: flag.capturingTeam?.color,
        capturedBy: flag.capturingUser?.username,
        capturedAt: flag.capturedAt,
        points: flag.points
      } : null
    }));

    const capturedCount = flags.filter(f => f.captured).length;

    res.json({ 
      flags,
      totalFlags: flags.length,
      capturedFlags: capturedCount,
      match: {
        id: match.id,
        name: match.name,
        status: match.status
      }
    });
  } catch (error) {
    console.error('Error fetching match flags:', error);
    res.status(500).json({ error: 'Failed to fetch match flags' });
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

// Setup Guacamole access for a specific user
router.post('/:id/setup-guacamole/:userId', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { id: matchId, userId } = req.params;
    
    const user = await User.findByPk(userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const match = await Match.findByPk(matchId);
    if (!match) {
      return res.status(404).json({ error: 'Match not found' });
    }

    console.log(`Setting up Guacamole access for user ${user.username} in match ${matchId}`);
    
    const result = await guacamoleService.setupUserAccess(user);
    
    if (result.success) {
      res.json({
        message: 'Guacamole access configured successfully',
        credentials: result.credentials
      });
    } else {
      res.status(500).json({ error: 'Failed to setup Guacamole access', details: result.error });
    }
  } catch (error) {
    console.error('Error setting up Guacamole access:', error);
    res.status(500).json({ error: 'Failed to setup Guacamole access' });
  }
});

// Setup Guacamole access for all team members
router.post('/:id/setup-team-guacamole/:teamId', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { id: matchId, teamId } = req.params;
    
    const match = await Match.findByPk(matchId);
    if (!match) {
      return res.status(404).json({ error: 'Match not found' });
    }

    console.log(`Setting up Guacamole access for team ${teamId} in match ${matchId}`);
    
    const result = await guacamoleService.setupTeamAccess(teamId);
    
    if (result.success) {
      res.json({
        message: 'Team Guacamole access configured successfully',
        teamName: result.teamName,
        results: result.results
      });
    } else {
      res.status(500).json({ error: 'Failed to setup team Guacamole access', details: result.error });
    }
  } catch (error) {
    console.error('Error setting up team Guacamole access:', error);
    res.status(500).json({ error: 'Failed to setup team Guacamole access' });
  }
});

// Test Guacamole connectivity
router.get('/test-guacamole', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const result = await guacamoleService.testConnection();
    
    if (result.success) {
      res.json({
        message: 'Guacamole connection test successful',
        status: result.status
      });
    } else {
      res.status(500).json({ error: 'Guacamole connection test failed', details: result.error });
    }
  } catch (error) {
    console.error('Error testing Guacamole connection:', error);
    res.status(500).json({ error: 'Failed to test Guacamole connection' });
  }
});

// Get VMs assigned to current user in a match
router.get('/:id/my-vms', authenticateToken, async (req, res) => {
  try {
    const matchId = req.params.id;
    const userId = req.user.id;

    const vms = await vmAssignmentService.getUserVMs(userId, matchId);
    
    res.json({
      success: true,
      vms: vms,
      count: vms.length
    });
  } catch (error) {
    console.error('Error getting user VMs:', error);
    res.status(500).json({ error: 'Failed to get user VMs' });
  }
});

// Get VMs assigned to a team in a match
router.get('/:id/team/:teamId/vms', authenticateToken, async (req, res) => {
  try {
    const matchId = req.params.id;
    const teamId = req.params.teamId;

    const vms = await vmAssignmentService.getTeamVMs(teamId, matchId);
    
    res.json({
      success: true,
      vms: vms,
      count: vms.length
    });
  } catch (error) {
    console.error('Error getting team VMs:', error);
    res.status(500).json({ error: 'Failed to get team VMs' });
  }
});

// Get VM pool status (admin only)
router.get('/vm-pool-status', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const status = vmAssignmentService.getVMPoolStatus();
    
    res.json({
      success: true,
      status: status
    });
  } catch (error) {
    console.error('Error getting VM pool status:', error);
    res.status(500).json({ error: 'Failed to get VM pool status' });
  }
});

module.exports = router;

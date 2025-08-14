const { User, Lab, FlagSubmission, WebLabCompletion, Team, Match, ScoringEvent } = require('../models');
const { Op } = require('sequelize');
const scoringService = require('../services/scoringService');

/**
 * Handles flag submission and awards points for correct submissions
 * @param {object} req The Express request object
 * @param {object} res The Express response object
 */
exports.submitFlag = async (req, res) => {
  try {
    const { labId, flag } = req.body;
    const userId = req.user.id;
    const userIP = req.ip || req.connection.remoteAddress;

    // Validate input
    if (!labId || !flag) {
      return res.status(400).json({ 
        message: 'Lab ID and flag are required',
        success: false 
      });
    }

    if (!flag.trim()) {
      return res.status(400).json({ 
        message: 'Flag cannot be empty',
        success: false 
      });
    }

    console.log(`[INFO] Flag submission attempt - User: ${userId}, Lab: ${labId}, Flag: ${flag}`);

    // Find the lab
    const lab = await Lab.findByPk(labId);
    if (!lab) {
      return res.status(404).json({ 
        message: 'Lab not found',
        success: false 
      });
    }

    // Check if user has already successfully submitted the flag for this lab
    const existingSuccessfulSubmission = await FlagSubmission.findOne({
      where: {
        userId,
        labId,
        isCorrect: true
      }
    });

    if (existingSuccessfulSubmission) {
      return res.status(409).json({
        message: 'You have already successfully completed this lab!',
        success: false,
        alreadyCompleted: true,
        completedAt: existingSuccessfulSubmission.submissionTime,
        pointsEarned: existingSuccessfulSubmission.pointsAwarded
      });
    }

    // Get the count of previous attempts for this user and lab
    const previousAttempts = await FlagSubmission.count({
      where: {
        userId,
        labId
      }
    });

    // Check if the submitted flag is correct
    const isCorrect = flag.trim().toLowerCase() === lab.flag.trim().toLowerCase();
    let pointsAwarded = 0;
    let timeExpired = false;
    let timeInfo = null;

    if (isCorrect) {
      // Check if time period has expired
      const timeCheck = await checkTimeExpiry(lab, userId);
      timeExpired = timeCheck.expired;
      timeInfo = timeCheck.info;

      if (timeExpired) {
        pointsAwarded = 0;
        console.log(`[INFO] Correct flag submitted but time expired! User: ${userId}, Lab: ${labId}, Points: 0`);
      } else {
        // Calculate points based on difficulty and attempt count
        pointsAwarded = calculatePoints(lab.points, lab.difficulty, previousAttempts + 1);
        console.log(`[INFO] Correct flag submitted! User: ${userId}, Lab: ${labId}, Points: ${pointsAwarded}`);
      }
    } else {
      console.log(`[INFO] Incorrect flag submitted - User: ${userId}, Lab: ${labId}`);
    }

    // Create flag submission record
    const submission = await FlagSubmission.create({
      userId,
      labId,
      submittedFlag: flag,
      isCorrect,
      pointsAwarded,
      submissionTime: new Date(),
      ipAddress: userIP,
      attemptCount: previousAttempts + 1,
      timeExpired: timeExpired || false // Add this field to track time expiry
    });

    // If correct and not time expired, update user's total points
    if (isCorrect && !timeExpired) {
      const user = await User.findByPk(userId);
      user.totalPoints += pointsAwarded;
      await user.save();

      console.log(`[INFO] User ${userId} total points updated: ${user.totalPoints} (+${pointsAwarded})`);

      return res.json({
        success: true,
        correct: true,
        message: 'Congratulations! You captured the flag!',
        pointsAwarded,
        totalPoints: user.totalPoints,
        attempt: previousAttempts + 1,
        submissionId: submission.id,
        timeInfo
      });
    } else if (isCorrect && timeExpired) {
      return res.json({
        success: true,
        correct: true,
        message: 'Flag is correct but time period has expired. No points awarded.',
        pointsAwarded: 0,
        attempt: previousAttempts + 1,
        submissionId: submission.id,
        timeExpired: true,
        timeInfo
      });
    } else {
      return res.json({
        success: true,
        correct: false,
        message: 'Incorrect flag. Try again!',
        pointsAwarded: 0,
        attempt: previousAttempts + 1,
        submissionId: submission.id,
        maxPoints: lab.points,
        currentPenalty: calculatePointPenalty(previousAttempts + 1),
        timeInfo
      });
    }

  } catch (error) {
    console.error('[ERROR] Flag submission error:', error);
    res.status(500).json({
      message: 'An error occurred while processing your flag submission',
      success: false,
      error: error.message
    });
  }
};

/**
 * Check if the time period for earning points has expired
 * @param {object} lab The lab object
 * @param {number} userId The user ID
 * @returns {object} Object containing expiry status and time info
 */
async function checkTimeExpiry(lab, userId) {
  try {
    // Option 1: If time period is stored in the lab table
    if (lab.timePeriodHours) {
      const labStartTime = lab.createdAt || lab.startTime; // Adjust field name as needed
      const currentTime = new Date();
      const timePeriodMs = lab.timePeriodHours * 60 * 60 * 1000; // Convert hours to milliseconds
      const expiryTime = new Date(labStartTime.getTime() + timePeriodMs);
      
      return {
        expired: currentTime > expiryTime,
        info: {
          labStartTime,
          expiryTime,
          currentTime,
          timePeriodHours: lab.timePeriodHours,
          timeRemaining: Math.max(0, expiryTime.getTime() - currentTime.getTime())
        }
      };
    }

    // Option 2: If time period is stored per user (user-specific start time)
    // You might have a UserLabSession table or similar
    const userLabSession = await UserLabSession.findOne({
      where: { userId, labId: lab.id }
    });

    if (userLabSession && userLabSession.startTime && lab.timePeriodHours) {
      const currentTime = new Date();
      const timePeriodMs = lab.timePeriodHours * 60 * 60 * 1000;
      const expiryTime = new Date(userLabSession.startTime.getTime() + timePeriodMs);
      
      return {
        expired: currentTime > expiryTime,
        info: {
          userStartTime: userLabSession.startTime,
          expiryTime,
          currentTime,
          timePeriodHours: lab.timePeriodHours,
          timeRemaining: Math.max(0, expiryTime.getTime() - currentTime.getTime())
        }
      };
    }

    // Option 3: Global time period from settings table
    const timeSetting = await Setting.findOne({
      where: { key: 'lab_time_period_hours' }
    });

    if (timeSetting && timeSetting.value) {
      const timePeriodHours = parseInt(timeSetting.value);
      const labStartTime = lab.createdAt || lab.startTime;
      const currentTime = new Date();
      const timePeriodMs = timePeriodHours * 60 * 60 * 1000;
      const expiryTime = new Date(labStartTime.getTime() + timePeriodMs);
      
      return {
        expired: currentTime > expiryTime,
        info: {
          labStartTime,
          expiryTime,
          currentTime,
          timePeriodHours,
          timeRemaining: Math.max(0, expiryTime.getTime() - currentTime.getTime())
        }
      };
    }

    // No time restriction found
    return {
      expired: false,
      info: {
        message: 'No time restriction set for this lab'
      }
    };

  } catch (error) {
    console.error('[ERROR] Time expiry check error:', error);
    // If there's an error checking time, don't penalize the user
    return {
      expired: false,
      info: {
        error: 'Could not verify time restriction'
      }
    };
  }
}

/**
 * Get flag submission history for a specific lab and user
 * @param {object} req The Express request object
 * @param {object} res The Express response object
 */
exports.getSubmissionHistory = async (req, res) => {
  try {
    const { labId } = req.params;
    const userId = req.user.id;

    if (!labId) {
      return res.status(400).json({ message: 'Lab ID is required' });
    }

    const submissions = await FlagSubmission.findAll({
      where: {
        userId,
        labId
      },
      include: [
        {
          model: Lab,
          as: 'lab',
          attributes: ['id', 'name', 'points', 'timePeriodHours']
        }
      ],
      order: [['submissionTime', 'DESC']]
    });

    res.json({
      submissions: submissions,
      totalAttempts: submissions.length,
      hasSuccessfulSubmission: submissions.some(s => s.isCorrect),
      lastAttempt: submissions.length > 0 ? submissions[0].submissionTime : null
    });

  } catch (error) {
    console.error('[ERROR] Get submission history error:', error);
    res.status(500).json({
      message: 'Failed to retrieve submission history',
      error: error.message
    });
  }
};

/**
 * Get user's overall statistics
 * @param {object} req The Express request object
 * @param {object} res The Express response object
 */
exports.getUserStats = async (req, res) => {
  try {
    const userId = req.user.id;

    const user = await User.findByPk(userId, {
      attributes: ['id', 'username', 'totalPoints']
    });

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Get VM lab completions count
    const vmLabsCompleted = await FlagSubmission.count({
      where: {
        userId,
        isCorrect: true
      }
    });

    // Get web lab completions count
    const webLabsCompleted = await WebLabCompletion.count({
      where: {
        userId
      }
    });

    // Total labs completed
    const totalLabsCompleted = vmLabsCompleted + webLabsCompleted;

    // Get total flag submissions count (only for VM labs)
    const totalSubmissions = await FlagSubmission.count({
      where: { userId }
    });

    // Get recent successful VM lab submissions with lab details
    const recentVMSuccesses = await FlagSubmission.findAll({
      where: {
        userId,
        isCorrect: true
      },
      include: [
        {
          model: Lab,
          as: 'lab',
          attributes: ['id', 'name', 'difficulty', 'points', 'labType']
        }
      ],
      order: [['submissionTime', 'DESC']],
      limit: 5
    });

    // Get recent web lab completions
    const recentWebSuccesses = await WebLabCompletion.findAll({
      where: {
        userId
      },
      include: [
        {
          model: Lab,
          as: 'lab',
          attributes: ['id', 'name', 'difficulty', 'points', 'labType']
        }
      ],
      order: [['completedAt', 'DESC']],
      limit: 5
    });

    // Combine and sort all recent completions
    const allRecentCompletions = [
      ...recentVMSuccesses.map(submission => ({
        id: submission.id,
        lab: submission.lab,
        completedAt: submission.submissionTime,
        pointsAwarded: submission.pointsAwarded,
        type: 'vm'
      })),
      ...recentWebSuccesses.map(completion => ({
        id: completion.id,
        lab: completion.lab,
        completedAt: completion.completedAt,
        pointsAwarded: completion.lab?.points || 0,
        type: 'web'
      }))
    ].sort((a, b) => new Date(b.completedAt) - new Date(a.completedAt)).slice(0, 10);

    // Calculate success rate for VM labs only (since web labs don't have attempts/failures)
    const successRate = totalSubmissions > 0 ? 
      ((vmLabsCompleted / totalSubmissions) * 100).toFixed(1) : 0;

    res.json({
      user: {
        id: user.id,
        username: user.username,
        totalPoints: user.totalPoints
      },
      stats: {
        labsCompleted: totalLabsCompleted,
        vmLabsCompleted,
        webLabsCompleted,
        totalSubmissions,
        successRate: parseFloat(successRate),
        recentCompletions: allRecentCompletions
      }
    });

  } catch (error) {
    console.error('[ERROR] Get user stats error:', error);
    res.status(500).json({
      message: 'Failed to retrieve user statistics',
      error: error.message
    });
  }
};

/**
 * Get leaderboard showing top users by points
 * @param {object} req The Express request object
 * @param {object} res The Express response object
 */
exports.getLeaderboard = async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 10;
    const page = parseInt(req.query.page) || 1;
    const offset = (page - 1) * limit;

    const users = await User.findAndCountAll({
      attributes: ['id', 'username', 'totalPoints'],
      order: [['totalPoints', 'DESC'], ['username', 'ASC']],
      limit,
      offset
    });

    // Get each user's lab completion count (both VM and web labs)
    const usersWithStats = await Promise.all(
      users.rows.map(async (user) => {
        // Count VM lab completions from FlagSubmission
        const vmLabsCompleted = await FlagSubmission.count({
          where: {
            userId: user.id,
            isCorrect: true
          }
        });

        // Count web lab completions from WebLabCompletion
        const webLabsCompleted = await WebLabCompletion.count({
          where: {
            userId: user.id
          }
        });

        // Total labs completed (VM + web)
        const labsCompleted = vmLabsCompleted + webLabsCompleted;

        return {
          id: user.id,
          username: user.username,
          totalPoints: user.totalPoints,
          labsCompleted
        };
      })
    );

    res.json({
      leaderboard: usersWithStats,
      pagination: {
        total: users.count,
        page,
        limit,
        totalPages: Math.ceil(users.count / limit)
      }
    });

  } catch (error) {
    console.error('[ERROR] Get leaderboard error:', error);
    res.status(500).json({
      message: 'Failed to retrieve leaderboard',
      error: error.message
    });
  }
};

/**
 * Calculate points based on lab base points, difficulty, and attempt number
 * @param {number} basePoints Base points for the lab
 * @param {string} difficulty Lab difficulty level
 * @param {number} attemptNumber Current attempt number (1-based)
 * @returns {number} Points to award
 */
function calculatePoints(basePoints, difficulty, attemptNumber) {
  let points = basePoints;

  // Difficulty multiplier
  const difficultyMultipliers = {
    'beginner': 1.0,
    'intermediate': 1.2,
    'advanced': 1.5
  };

  points *= (difficultyMultipliers[difficulty] || 1.0);

  // Penalty for multiple attempts (10% reduction per additional attempt)
  if (attemptNumber > 1) {
    const penalty = Math.min(0.7, (attemptNumber - 1) * 0.1); // Max 70% penalty
    points *= (1 - penalty);
  }

  return Math.max(1, Math.floor(points)); // Minimum 1 point, rounded down
}

/**
 * Submit flag in cyber-warfare mode (team-based matches)
 * @param {object} req The Express request object
 * @param {object} res The Express response object
 */
exports.submitCyberwarFlag = async (req, res) => {
  try {
    const { matchId, teamId, flag, eventType = 'flag_capture', description } = req.body;
    const userId = req.user.id;
    const userIP = req.ip || req.connection.remoteAddress;

    // Validate input
    if (!matchId || !teamId || !flag) {
      return res.status(400).json({ 
        message: 'Match ID, Team ID, and flag are required',
        success: false 
      });
    }

    // Verify user is member of the team
    const user = await User.findByPk(userId, {
      include: [{
        model: Team,
        as: 'teams',
        where: { id: teamId },
        required: false
      }]
    });

    if (!user || user.teams.length === 0) {
      return res.status(403).json({
        message: 'You are not a member of this team',
        success: false
      });
    }

    // Verify match is active
    const match = await Match.findByPk(matchId, {
      include: [{
        model: Team,
        as: 'teams',
        where: { id: teamId }
      }]
    });

    if (!match) {
      return res.status(404).json({
        message: 'Match not found or team not in match',
        success: false
      });
    }

    if (match.status !== 'active') {
      return res.status(400).json({
        message: 'Match is not currently active',
        success: false
      });
    }

    // Check for duplicate flag submission
    const existingSubmission = await FlagSubmission.findOne({
      where: {
        matchId,
        teamId,
        submittedFlag: flag.trim(),
        isCorrect: true
      }
    });

    if (existingSubmission) {
      return res.status(409).json({
        message: 'This flag has already been captured by your team',
        success: false,
        alreadyCaptured: true
      });
    }

    // Define cyber-warfare flags and their point values
    const cyberwarFlags = {
      // Network reconnaissance flags
      'CYBERWAR{network_discovery}': { points: 25, type: 'network_compromise' },
      'CYBERWAR{port_scan_complete}': { points: 20, type: 'network_compromise' },
      'CYBERWAR{service_enumeration}': { points: 30, type: 'network_compromise' },
      
      // Vulnerability exploitation flags
      'CYBERWAR{smb_exploit_success}': { points: 50, type: 'vulnerability_exploit' },
      'CYBERWAR{rdp_brute_force}': { points: 40, type: 'vulnerability_exploit' },
      'CYBERWAR{web_shell_upload}': { points: 60, type: 'vulnerability_exploit' },
      
      // System compromise flags
      'CYBERWAR{system_access}': { points: 75, type: 'attack_success' },
      'CYBERWAR{privilege_escalation}': { points: 80, type: 'attack_success' },
      'CYBERWAR{persistence_established}': { points: 85, type: 'attack_success' },
      
      // Data exfiltration flags
      'CYBERWAR{sensitive_data_found}': { points: 70, type: 'lateral_movement' },
      'CYBERWAR{database_compromised}': { points: 90, type: 'lateral_movement' },
      'CYBERWAR{admin_credentials}': { points: 100, type: 'lateral_movement' },
      
      // Defense flags (for blue team activities)
      'CYBERWAR{intrusion_detected}': { points: 45, type: 'defense_action' },
      'CYBERWAR{malware_quarantined}': { points: 55, type: 'defense_action' },
      'CYBERWAR{vulnerability_patched}': { points: 40, type: 'defense_action' },
      
      // Special achievement flags
      'CYBERWAR{stealth_master}': { points: 120, type: 'stealth_achievement' },
      'CYBERWAR{full_domain_control}': { points: 150, type: 'full_compromise' }
    };

    const flagData = cyberwarFlags[flag.trim().toUpperCase()];
    const isCorrect = !!flagData;
    let pointsAwarded = 0;
    let finalEventType = eventType;

    if (isCorrect) {
      pointsAwarded = flagData.points;
      finalEventType = flagData.type;
      console.log(`[CYBERWAR] Correct flag captured! Team: ${teamId}, Match: ${matchId}, Flag: ${flag}, Points: ${pointsAwarded}`);
    } else {
      console.log(`[CYBERWAR] Invalid flag attempted - Team: ${teamId}, Match: ${matchId}, Flag: ${flag}`);
    }

    // Create flag submission record
    const submission = await FlagSubmission.create({
      userId,
      teamId,
      matchId,
      submittedFlag: flag,
      isCorrect,
      pointsAwarded,
      submissionTime: new Date(),
      ipAddress: userIP,
      eventType: finalEventType,
      description: description || (isCorrect ? `Flag captured: ${flag}` : `Invalid flag attempt: ${flag}`)
    });

    // If correct, create scoring event and update team score
    if (isCorrect) {
      // Create detailed scoring event
      const scoringEvent = await ScoringEvent.create({
        matchId,
        teamId,
        userId,
        eventType: finalEventType,
        eventSubtype: flag.trim(),
        basePoints: pointsAwarded,
        finalPoints: pointsAwarded,
        confidence: 1.0, // Manual flag submission has 100% confidence
        description: description || `Flag captured: ${flag}`,
        sourceType: 'manual_flag',
        evidence: {
          flagValue: flag,
          submissionIP: userIP,
          submissionId: submission.id
        },
        isVerified: true,
        verifiedBy: userId,
        submissionId: submission.id
      });

      // Update team score and statistics
      const team = await Team.findByPk(teamId);
      if (team) {
        team.currentPoints = (team.currentPoints || 0) + pointsAwarded;
        team.totalFlags = (team.totalFlags || 0) + 1;
        team.lastActivity = new Date();
        await team.save();
      }

      // Broadcast scoring event via WebSocket
      if (scoringService.wss) {
        await scoringService.broadcastScoringEvent(matchId, scoringEvent);
      }

      // Log for analysis
      console.log(`[CYBERWAR] Scoring event created: Match ${matchId}, Team ${teamId}, Points: +${pointsAwarded}`);

      return res.json({
        success: true,
        correct: true,
        message: 'Flag captured successfully!',
        pointsAwarded,
        eventType: finalEventType,
        teamScore: team.currentPoints,
        submissionId: submission.id,
        scoringEventId: scoringEvent.id,
        flagType: flagData.type,
        timestamp: new Date()
      });
    } else {
      return res.json({
        success: true,
        correct: false,
        message: 'Invalid flag. Keep attacking!',
        pointsAwarded: 0,
        submissionId: submission.id,
        timestamp: new Date()
      });
    }

  } catch (error) {
    console.error('[ERROR] Cyber-warfare flag submission error:', error);
    res.status(500).json({
      message: 'An error occurred while processing your flag submission',
      success: false,
      error: error.message
    });
  }
};

/**
 * Get match scoreboard with real-time team standings
 * @param {object} req The Express request object  
 * @param {object} res The Express response object
 */
exports.getMatchScoreboard = async (req, res) => {
  try {
    const { matchId } = req.params;

    const match = await Match.findByPk(matchId, {
      include: [{
        model: Team,
        as: 'teams',
        include: [{
          model: ScoringEvent,
          as: 'scoringEvents',
          where: { matchId, isActive: true },
          required: false,
          order: [['createdAt', 'DESC']]
        }]
      }]
    });

    if (!match) {
      return res.status(404).json({ message: 'Match not found' });
    }

    // Build scoreboard data
    const scoreboard = match.teams.map(team => {
      const recentEvents = team.scoringEvents.slice(0, 5).map(event => ({
        type: event.eventType,
        points: event.finalPoints,
        description: event.description,
        timestamp: event.createdAt,
        confidence: event.confidence
      }));

      return {
        id: team.id,
        name: team.name,
        color: team.color,
        currentPoints: team.currentPoints || 0,
        totalFlags: team.totalFlags || 0,
        lastActivity: team.lastActivity,
        recentEvents,
        eventBreakdown: team.scoringEvents.reduce((breakdown, event) => {
          breakdown[event.eventType] = (breakdown[event.eventType] || 0) + 1;
          return breakdown;
        }, {})
      };
    }).sort((a, b) => b.currentPoints - a.currentPoints);

    // Add rank information
    scoreboard.forEach((team, index) => {
      team.rank = index + 1;
    });

    res.json({
      match: {
        id: match.id,
        name: match.name,
        status: match.status,
        startTime: match.startTime,
        duration: match.duration
      },
      scoreboard,
      lastUpdate: new Date(),
      totalEvents: match.teams.reduce((total, team) => 
        total + team.scoringEvents.length, 0
      )
    });

  } catch (error) {
    console.error('[ERROR] Get match scoreboard error:', error);
    res.status(500).json({
      message: 'Failed to retrieve match scoreboard',
      error: error.message
    });
  }
};

/**
 * Get live match events stream
 * @param {object} req The Express request object
 * @param {object} res The Express response object  
 */
exports.getMatchEvents = async (req, res) => {
  try {
    const { matchId } = req.params;
    const limit = parseInt(req.query.limit) || 20;
    const eventType = req.query.type;
    const teamId = req.query.teamId;

    const whereClause = { matchId, isActive: true };
    if (eventType) whereClause.eventType = eventType;
    if (teamId) whereClause.teamId = teamId;

    const events = await ScoringEvent.findAll({
      where: whereClause,
      include: [
        {
          model: Team,
          as: 'team',
          attributes: ['id', 'name', 'color']
        },
        {
          model: User,
          as: 'user',
          attributes: ['id', 'username']
        }
      ],
      order: [['createdAt', 'DESC']],
      limit
    });

    const formattedEvents = events.map(event => ({
      id: event.id,
      type: event.eventType,
      subtype: event.eventSubtype,
      points: event.finalPoints,
      team: {
        id: event.team.id,
        name: event.team.name,
        color: event.team.color
      },
      user: event.user ? {
        id: event.user.id,
        username: event.user.username
      } : null,
      description: event.description,
      timestamp: event.createdAt,
      confidence: event.confidence,
      sourceType: event.sourceType,
      isVerified: event.isVerified
    }));

    res.json({
      matchId,
      events: formattedEvents,
      totalCount: events.length,
      filters: {
        eventType,
        teamId,
        limit
      },
      lastUpdate: new Date()
    });

  } catch (error) {
    console.error('[ERROR] Get match events error:', error);
    res.status(500).json({
      message: 'Failed to retrieve match events',
      error: error.message
    });
  }
};

/**
 * Calculate point penalty percentage for display purposes
 * @param {number} attemptNumber Current attempt number (1-based)
 * @returns {number} Penalty percentage (0-70)
 */
function calculatePointPenalty(attemptNumber) {
  if (attemptNumber <= 1) return 0;
  return Math.min(70, (attemptNumber - 1) * 10);
}

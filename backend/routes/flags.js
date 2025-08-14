const express = require('express');
const router = express.Router();
const { 
  submitFlag, 
  getSubmissionHistory, 
  getUserStats, 
  getLeaderboard,
  submitCyberwarFlag,
  getMatchScoreboard,
  getMatchEvents
} = require('../controllers/flagController');
const { auth } = require('../middleware/auth');

// All routes require authentication
router.use(auth);

/**
 * @route   POST /api/flags/submit
 * @desc    Submit a flag for a lab
 * @access  Private (authenticated users)
 */
router.post('/submit', submitFlag);

/**
 * @route   GET /api/flags/history/:labId
 * @desc    Get flag submission history for a specific lab and user
 * @access  Private (authenticated users)
 */
router.get('/history/:labId', getSubmissionHistory);

/**
 * @route   GET /api/flags/user-stats
 * @desc    Get user's overall statistics including points and completed labs
 * @access  Private (authenticated users)
 */
router.get('/user-stats', getUserStats);

/**
 * @route   GET /api/flags/leaderboard
 * @desc    Get leaderboard showing top users by points
 * @access  Private (authenticated users)
 * @query   ?limit=10&page=1
 */
router.get('/leaderboard', getLeaderboard);

/**
 * @route   POST /api/flags/cyberwar/submit
 * @desc    Submit a flag in cyber-warfare mode (team-based matches)
 * @access  Private (authenticated team members)
 */
router.post('/cyberwar/submit', submitCyberwarFlag);

/**
 * @route   GET /api/flags/match/:matchId/scoreboard
 * @desc    Get real-time scoreboard for a match
 * @access  Private (authenticated users)
 */
router.get('/match/:matchId/scoreboard', getMatchScoreboard);

/**
 * @route   GET /api/flags/match/:matchId/events
 * @desc    Get live events stream for a match
 * @access  Private (authenticated users)
 * @query   ?limit=20&type=flag_capture&teamId=1
 */
router.get('/match/:matchId/events', getMatchEvents);

module.exports = router;

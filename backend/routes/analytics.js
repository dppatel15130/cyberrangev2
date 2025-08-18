const express = require('express');
const router = express.Router();
const { auth: authenticateToken } = require('../middleware/auth');
const analyticsController = require('../controllers/analyticsController');

/**
 * @route   GET /api/analytics/performance
 * @desc    Get performance metrics over time
 * @access  Private
 */
router.get('/performance', authenticateToken, analyticsController.getPerformanceData);

/**
 * @route   GET /api/analytics/categories
 * @desc    Get category distribution
 * @access  Private
 */
router.get('/categories', authenticateToken, analyticsController.getCategoryData);

/**
 * @route   GET /api/teams/stats
 * @desc    Get team statistics and leaderboard position
 * @access  Private
 */
router.get('/teams/stats', authenticateToken, analyticsController.getTeamStats);

module.exports = router;

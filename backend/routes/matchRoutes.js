const express = require('express');
const router = express.Router();
const { auth: authenticateToken, admin } = require('../middleware/auth');
const matchController = require('../controllers/matchController');

// Apply authentication middleware to all routes
router.use(authenticateToken);

/**
 * @route   POST /api/matches
 * @desc    Create a new match (admin only)
 * @access  Private/Admin
 */
router.post('/', admin, matchController.createMatch);

/**
 * @route   GET /api/matches
 * @desc    Get all matches
 * @access  Private
 */
router.get('/', matchController.getMatches);

/**
 * @route   GET /api/matches/:id
 * @desc    Get match by ID
 * @access  Private
 */
router.get('/:id', matchController.getMatchById);

/**
 * @route   PUT /api/matches/:id
 * @desc    Update match (admin only)
 * @access  Private/Admin
 */
router.put('/:id', admin, matchController.updateMatch);

/**
 * @route   DELETE /api/matches/:id
 * @desc    Delete match (admin only)
 * @access  Private/Admin
 */
router.delete('/:id', admin, matchController.deleteMatch);

/**
 * @route   POST /api/matches/:id/start
 * @desc    Start a match (admin only)
 * @access  Private/Admin
 */
router.post('/:id/start', admin, matchController.startMatch);

/**
 * @route   POST /api/matches/:id/end
 * @desc    End a match (admin only)
 * @access  Private/Admin
 */
router.post('/:id/end', admin, matchController.endMatch);

module.exports = router;

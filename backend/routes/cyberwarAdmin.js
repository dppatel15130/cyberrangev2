const express = require('express');
const router = express.Router();
const { auth: authenticateToken, admin } = require('../middleware/auth');
const cyberwarAdminController = require('../controllers/cyberwarAdminController');

// Apply authentication and admin middleware to all routes
router.use((req, res, next) => {
  // First authenticate the token
  authenticateToken(req, res, (authErr) => {
    if (authErr) {
      console.error('Authentication failed:', authErr);
      return next(authErr);
    }
    
    // Then check admin role
    admin(req, res, (adminErr) => {
      if (adminErr) {
        console.error('Admin check failed:', adminErr);
        return next(adminErr);
      }
      next();
    });
  });
});

// Debug route to check authentication
router.get('/debug', (req, res) => {
  console.log('Debug route - User:', req.user);
  res.json({
    authenticated: !!req.user,
    user: req.user || null,
    timestamp: new Date().toISOString()
  });
});

/**
 * @route   GET /api/admin/cyberwar/stats
 * @desc    Get admin dashboard statistics
 * @access  Private/Admin
 */
router.get('/stats', cyberwarAdminController.getAdminStats);

/**
 * @route   GET /api/admin/cyberwar/users
 * @desc    Get all users (admin only)
 * @access  Private/Admin
 */
router.get('/users', cyberwarAdminController.getAdminUsers);

/**
 * @route   POST /api/admin/cyberwar/users/:userId/:action
 * @desc    Perform action on user (activate/deactivate/delete)
 * @access  Private/Admin
 */
router.post('/users/:userId/:action', cyberwarAdminController.userAction);

/**
 * @route   GET /api/admin/cyberwar/flags
 * @desc    Get all flag submissions (admin only)
 * @access  Private/Admin
 */
router.get('/flags', cyberwarAdminController.getAdminFlags);

/**
 * @route   GET /api/admin/cyberwar/vms
 * @desc    Get all VMs (admin only)
 * @access  Private/Admin
 */
router.get('/vms', cyberwarAdminController.getAdminVMs);
// Add these routes to your cyberwar admin router

/**
 * @route GET /api/admin/cyberwar/matches
 * @desc Get all matches (admin only)
 * @access Private/Admin
 */
router.get('/matches', async (req, res) => {
  try {
    // Return empty array for now, implement Match model later
    res.json({ matches: [] });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch matches' });
  }
});

/**
 * @route GET /api/admin/cyberwar/teams
 * @desc Get all teams (admin only)
 * @access Private/Admin
 */
router.get('/teams', async (req, res) => {
  try {
    // Return empty array for now, implement Team model later
    res.json({ teams: [] });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch teams' });
  }
});

/**
 * @route POST /api/admin/cyberwar/matches
 * @desc Create new match (admin only)
 * @access Private/Admin
 */
router.post('/matches', async (req, res) => {
  try {
    // Implement match creation later
    res.json({ message: 'Match creation not implemented yet' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to create match' });
  }
});

/**
 * @route POST /api/admin/cyberwar/flags
 * @desc Create new flag (admin only)
 * @access Private/Admin
 */
router.post('/flags', async (req, res) => {
  try {
    // Implement flag creation later
    res.json({ message: 'Flag creation not implemented yet' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to create flag' });
  }
});
module.exports = router;

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
router.get('/matches', cyberwarAdminController.getAdminMatches);

/**
 * @route GET /api/admin/cyberwar/teams
 * @desc Get all teams (admin only)
 * @access Private/Admin
 */
router.get('/teams', cyberwarAdminController.getAdminTeams);

/**
 * @route POST /api/admin/cyberwar/matches
 * @desc Create new match (admin only)
 * @access Private/Admin
 */
router.post('/matches', cyberwarAdminController.createMatch);

/**
 * @route PUT /api/admin/cyberwar/matches/:id
 * @desc Update existing match (admin only)
 * @access Private/Admin
 */
router.put('/matches/:id', cyberwarAdminController.updateMatch);

/**
 * @route DELETE /api/admin/cyberwar/matches/:id
 * @desc Delete match (admin only)
 * @access Private/Admin
 */
router.delete('/matches/:id', cyberwarAdminController.deleteMatch);

/**
 * @route GET /api/admin/cyberwar/flags
 * @desc Get all flags (admin only)
 * @access Private/Admin
 */
router.get('/flags', cyberwarAdminController.getAdminFlags);

/**
 * @route POST /api/admin/cyberwar/flags
 * @desc Create new flag (admin only)
 * @access Private/Admin
 */
router.post('/flags', cyberwarAdminController.createFlag);

/**
 * @route PUT /api/admin/cyberwar/flags/:id
 * @desc Update existing flag (admin only)
 * @access Private/Admin
 */
router.put('/flags/:id', cyberwarAdminController.updateFlag);

/**
 * @route DELETE /api/admin/cyberwar/flags/:id
 * @desc Delete flag (admin only)
 * @access Private/Admin
 */
router.delete('/flags/:id', cyberwarAdminController.deleteFlag);
module.exports = router;

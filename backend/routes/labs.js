const express = require('express');
const router = express.Router();
const labController = require('../controllers/labController');
const { auth, admin } = require('../middleware/auth');

// Log all requests to labs routes
router.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.originalUrl}`);
  console.log('Headers:', JSON.stringify(req.headers, null, 2));
  console.log('Query:', JSON.stringify(req.query, null, 2));
  console.log('Params:', JSON.stringify(req.params, null, 2));
  console.log('Body:', JSON.stringify(req.body, null, 2));
  next();
});

// @route   POST /api/labs
// @desc    Create a new lab
// @access  Admin only
router.post('/', auth, admin, labController.createLab);

// @route   GET /api/labs
// @desc    Get all labs (admin) or assigned labs (user)
// @access  Private
router.get('/', auth, labController.getAllLabs);

// @route   GET /api/labs/:id
// @desc    Get lab by ID
// @access  Private (admin or assigned user)
router.get('/:id', auth, labController.getLabById);

// @route   PUT /api/labs/:id
// @desc    Update lab
// @access  Admin only
router.put('/:id', auth, admin, labController.updateLab);

// @route   DELETE /api/labs/:id
// @desc    Delete lab
// @access  Admin only
router.delete('/:id', auth, admin, labController.deleteLab);

// @route   POST /api/labs/assign
// @desc    Assign lab to users
// @access  Admin only
router.post('/assign', auth, admin, labController.assignLab);

// @route   POST /api/labs/unassign
// @desc    Unassign lab from users
// @access  Admin only
router.post('/unassign', auth, admin, labController.unassignLab);

// @route   POST /api/labs/draft
// @desc    Save lab as draft
// @access  Admin only
router.post('/draft', auth, admin, labController.saveDraft);

// @route   PUT /api/labs/:id/draft
// @desc    Update existing draft
// @access  Admin only
router.put('/:id/draft', auth, admin, labController.saveDraft);

// @route   PUT /api/labs/:id/publish
// @desc    Publish lab from draft
// @access  Admin only
router.put('/:id/publish', auth, admin, labController.publishLab);

// @route   PUT /api/labs/:id/archive
// @desc    Archive lab
// @access  Admin only
router.put('/:id/archive', auth, admin, labController.archiveLab);

// @route   GET /api/labs/statistics
// @desc    Get lab statistics
// @access  Admin only
router.get('/statistics', auth, admin, labController.getLabStatistics);

module.exports = router;

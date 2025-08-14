const express = require('express');
const router = express.Router();
const { check } = require('express-validator');
const webLabController = require('../controllers/webLabController');
const { auth, admin } = require('../middleware/auth');

// @route   POST /api/weblabs
// @desc    Create a new web lab (admin only)
// @access  Private/Admin
router.post(
  '/',
  [
    auth,
    admin,
    [
      check('name', 'Name is required').not().isEmpty(),
      check('description', 'Description is required').not().isEmpty(),
      check('category', 'Category is required').not().isEmpty(),
      check('difficulty', 'Difficulty is required').isIn(['beginner', 'intermediate', 'advanced']),
      check('instructions', 'Instructions are required').not().isEmpty(),
      check('htmlContent', 'HTML content is required when hostedUrl is not provided')
        .if((value, { req }) => !req.body.hostedUrl)
        .not().isEmpty(),
      check('hostedUrl', 'Hosted URL is required when htmlContent is not provided')
        .if((value, { req }) => !req.body.htmlContent)
        .not().isEmpty()
        .isURL({ 
          require_protocol: true, 
          require_tld: false,
          allow_underscores: true,
          allow_trailing_dot: true
        })
        .custom((value) => {
          try {
            const url = new URL(value);
            // Allow localhost and 127.0.0.1
            if (!['localhost', '127.0.0.1'].includes(url.hostname)) {
              throw new Error('Hosted URL must point to localhost or 127.0.0.1');
            }
            return true;
          } catch (e) {
            throw new Error('Must be a valid URL');
          }
        }),
      check('validationType', 'Validation type must be either header_check, input_flag, or callback')
        .isIn(['header_check', 'input_flag', 'callback']),
      check('validationValue', 'Validation value is required').not().isEmpty(),
      check('points', 'Points must be a positive integer').optional().isInt({ min: 1 })
    ]
  ],
  webLabController.createWebLab
);

// @route   PUT /api/weblabs/:id
// @desc    Update a web lab (admin only)
// @access  Private/Admin
router.put(
  '/:id',
  [
    auth,
    admin,
    [
      check('name', 'Name is required').optional().not().isEmpty(),
      check('description', 'Description is required').optional().not().isEmpty(),
      check('category', 'Category is required').optional().not().isEmpty(),
      check('difficulty', 'Invalid difficulty')
        .optional()
        .isIn(['beginner', 'intermediate', 'advanced']),
      check('instructions', 'Instructions are required').optional().not().isEmpty(),
      check('htmlContent', 'HTML content is required when hostedUrl is not provided')
        .optional()
        .if((value, { req }) => !req.body.hostedUrl && req.body.htmlContent !== undefined)
        .not().isEmpty(),
      check('hostedUrl', 'Hosted URL must be a valid URL')
        .optional()
        .isURL({ require_protocol: true }),
      check('validationType', 'Validation type must be either header_check, input_flag, or callback')
        .optional()
        .isIn(['header_check', 'input_flag', 'callback']),
      check('validationValue', 'Validation value is required').optional().not().isEmpty(),
      check('points', 'Points must be a positive integer').optional().isInt({ min: 1 })
    ]
  ],
  webLabController.updateWebLab
);

// @route   GET /api/weblabs/status-check/:id
// @desc    Status check endpoint for header-based validation or redirect to external lab
// @access  Public (used by iframe or for redirection)
router.get('/status-check/:id', webLabController.statusCheck);

// @route   GET /api/weblabs/:id
// @desc    Get web lab by ID
// @access  Private
router.get('/:id', auth, webLabController.getWebLab);

// @route   GET /api/weblabs/:id/status
// @desc    Check if the lab is completed by the current user
// @access  Private
router.get('/:id/status', auth, webLabController.checkLabStatus);

// @route   POST /api/weblabs/:id/complete
// @desc    Mark a lab as complete via callback from external lab
// @access  Public (with token validation in controller)
router.post('/:id/complete', webLabController.completeLabCallback);

// @route   POST /api/weblabs/:id/submit
// @desc    Submit web lab solution
// @access  Private
router.post(
  '/:id/submit',
  [
    auth,
    [
      check('flag', 'Flag is required for input_flag validation type')
        .if((_, { req }) => req.body.validationType === 'input_flag')
        .notEmpty(),
      check('headers', 'Headers must be an object').optional().isObject()
    ]
  ],
  webLabController.submitWebLab
);

// @route   GET /api/weblabs/:id/submissions
// @desc    Get all submissions for a web lab (admin only)
// @access  Private/Admin
router.get('/:id/submissions', [auth, admin], webLabController.getWebLabSubmissions);

// @route   GET /api/weblabs
// @desc    Get all web labs (admin only)
// @access  Private/Admin
router.get('/', [auth, admin], webLabController.getAllWebLabs);

// @route   DELETE /api/weblabs/:id
// @desc    Delete a web lab (admin only)
// @access  Private/Admin
router.delete('/:id', [auth, admin], webLabController.deleteWebLab);

module.exports = router;

const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const { auth, admin } = require('../middleware/auth');
const loggers = require('../config/logger');

// @route   POST /api/auth/register
// @desc    Register a new user
// @access  Admin only
router.post('/register', auth, admin, authController.register);

// @route   POST /api/auth/login
// @desc    Login user and get token
// @access  Public
router.post('/login', authController.login);

// @route   GET /api/auth/me
// @desc    Get current user
// @access  Private
router.get('/me', auth, authController.getCurrentUser);

// @route   GET /api/auth/users
// @desc    Get all users
// @access  Admin only
router.get('/users', auth, admin, authController.getAllUsers);


// @route   PUT /api/auth/users/role
// @desc    Update user role
// @access  Admin only
router.put('/users/role', auth, admin, authController.updateUserRole);

// @route   DELETE /api/auth/users/:id
// @desc    Delete a user
// @access  Admin only
router.delete('/users/:id', auth, admin, authController.deleteUser);

// Alias for backward compatibility
router.delete('/:id', auth, admin, authController.deleteUser);

module.exports = router;
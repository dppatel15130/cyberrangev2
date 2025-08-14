const jwt = require('jsonwebtoken');
const { User } = require('../models');
const { Op } = require('sequelize');
const loggers = require('../config/logger');

// Register a new user
exports.register = async (req, res) => {
  try {
    const { username, email, password, role } = req.body;

    loggers.logAuth('REGISTRATION_ATTEMPT', null, {
      username,
      email,
      role: role || 'blue_team',
      requestedBy: req.user.id,
      ip: req.ip
    });

    // Check if user already exists
    const existingUser = await User.findOne({
      where: {
        [Op.or]: [{ email }, { username }]
      }
    });
    
    if (existingUser) {
      loggers.logAuth('REGISTRATION_FAILED', null, {
        reason: 'User already exists',
        username,
        email,
        ip: req.ip
      });
      return res.status(400).json({ message: 'User already exists' });
    }

    // Create new user
    const user = await User.create({
      username,
      email,
      password,
      role: role || 'blue_team', // Default to blue team if not specified
    });

    loggers.logAuth('USER_CREATED', user.id, {
      username: user.username,
      email: user.email,
      role: user.role,
      createdBy: req.user.id,
      ip: req.ip
    });

    loggers.logUser('CREATE', req.user.id, user.id, {
      username: user.username,
      role: user.role
    });

    // Generate JWT token with username in payload
    const token = jwt.sign(
      { 
        id: user.id, 
        username: user.username, // Include username in JWT payload
        role: user.role 
      },
      process.env.JWT_SECRET,
      { expiresIn: '1d' }
    );

    res.status(201).json({
      token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role,
      },
    });
  } catch (error) {
    loggers.logError(error, req, {
      operation: 'USER_REGISTRATION',
      requestData: { username: req.body.username, email: req.body.email }
    });
    console.error('Registration error:', error);
    res.status(500).json({ message: 'Server error during registration' });
  }
};

// Login user
exports.login = async (req, res) => {
  try {
    const { username, password } = req.body;

    loggers.logAuth('LOGIN_ATTEMPT', null, {
      username,
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });

    // Find user by username
    const user = await User.findOne({ where: { username } });
    if (!user) {
      loggers.logAuth('LOGIN_FAILED', null, {
        username,
        reason: 'User not found',
        ip: req.ip
      });
      loggers.logSecurity('INVALID_LOGIN_ATTEMPT', {
        username,
        ip: req.ip,
        reason: 'User not found'
      });
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // Check password
    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      loggers.logAuth('LOGIN_FAILED', user.id, {
        username,
        reason: 'Invalid password',
        ip: req.ip
      });
      loggers.logSecurity('INVALID_LOGIN_ATTEMPT', {
        username,
        userId: user.id,
        ip: req.ip,
        reason: 'Invalid password'
      });
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    loggers.logAuth('LOGIN_SUCCESS', user.id, {
      username: user.username,
      role: user.role,
      ip: req.ip
    });

    // Generate JWT token with username in payload
    const token = jwt.sign(
      { 
        id: user.id, 
        username: user.username, // Include username in JWT payload
        role: user.role 
      },
      process.env.JWT_SECRET,
      { expiresIn: '1d' }
    );

    res.json({
      token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role,
      },
    });
  } catch (error) {
    loggers.logError(error, req, {
      operation: 'USER_LOGIN',
      username: req.body.username
    });
    console.error('Login error:', error);
    res.status(500).json({ message: 'Server error during login' });
  }
};

// Get current user
exports.getCurrentUser = async (req, res) => {
  try {
    const user = await User.findByPk(req.user.id, {
      attributes: { exclude: ['password'] }
    });
    
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.json(user);
  } catch (error) {
    console.error('Get current user error:', error);
    res.status(500).json({ message: 'Server error' });
  }
};

// Get all users (admin only)
exports.getAllUsers = async (req, res) => {
  try {
    const users = await User.findAll({
      attributes: { exclude: ['password'] }
    });
    res.json(users);
  } catch (error) {
    console.error('Get all users error:', error);
    res.status(500).json({ message: 'Server error' });
  }
};

// Update user role (admin only)
exports.updateUserRole = async (req, res) => {
  try {
    const { userId, role } = req.body;
    
    if (!['admin', 'red_team', 'blue_team'].includes(role)) {
      return res.status(400).json({ message: 'Invalid role' });
    }

    const user = await User.findByPk(userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    user.role = role;
    await user.save();

    const userResponse = user.toJSON();
    delete userResponse.password;

    res.json(userResponse);
  } catch (error) {
    console.error('Update user role error:', error);
    res.status(500).json({ message: 'Server error' });
  }
};

// Delete user (admin only)
exports.deleteUser = async (req, res) => {
  try {
    const userId = req.params.id;
    
    // Prevent deleting self
    if (req.user.id === userId) {
      return res.status(400).json({ message: 'You cannot delete your own account' });
    }

    const user = await User.findByPk(userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Prevent deleting admin users
    if (user.role === 'admin') {
      return res.status(403).json({ message: 'Cannot delete admin users' });
    }

    await user.destroy();
    res.json({ message: 'User deleted successfully' });
  } catch (error) {
    console.error('Error deleting user:', error);
    res.status(500).json({ message: 'Server error during user deletion' });
  }
};

// Initialize admin user if not exists
exports.initializeAdmin = async () => {
  try {
    // Check if admin exists
    const adminExists = await User.findOne({ where: { role: 'admin' } });
    
    if (!adminExists) {
      // Create admin user
      await User.create({
        username: 'admin',
        email: 'admin@gmail.com',
        password: 'admin123', // This will be hashed by the beforeCreate hook
        role: 'admin',
      });
      
      console.log('Admin user created successfully');
    }
  } catch (error) {
    console.error('Admin initialization error:', error);
  }
};
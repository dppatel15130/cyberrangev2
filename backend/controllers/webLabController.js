const { Lab, WebLab, User, FlagSubmission, WebLabCompletion } = require('../models');
const { sequelize } = require('../config/db');
const { validationResult } = require('express-validator');
const { v4: uuidv4 } = require('uuid');

// Create a new web lab (admin only)
exports.createWebLab = async (req, res) => {
  const transaction = await sequelize.transaction();
  
  try {
    const { 
      name, 
      description, 
      category, 
      difficulty, 
      instructions, 
      htmlContent, 
      validationType, 
      validationValue, 
      allowedOrigins = [],
      points = 100,
      hostedUrl
    } = req.body;

    // Create the base lab
    const lab = await Lab.create({
      name,
      description,
      category,
      difficulty,
      instructions,
      labType: 'web',
      points: parseInt(points) || 100,
      createdBy: req.user.id
    }, { transaction });

    // Create the web lab specific data
    const webLab = await WebLab.create({
      labId: lab.id,
      htmlContent: htmlContent || '',
      validationType,
      validationValue,
      hostedUrl,
      allowedOrigins: Array.isArray(allowedOrigins) ? allowedOrigins.join(',') : (allowedOrigins || '')
    }, { transaction });
    
    // Associate the web lab with the lab
    await lab.setWebLabData(webLab, { transaction });

    await transaction.commit();
    
    res.status(201).json({
      ...lab.toJSON(),
      webLab: webLab.toJSON()
    });
  } catch (error) {
    await transaction.rollback();
    console.error('Error creating web lab:', {
      message: error.message,
      name: error.name,
      stack: error.stack,
      ...(error.errors && { errors: error.errors.map(e => e.message) }),
      ...(error.parent && { sqlError: error.parent.message, sql: error.parent.sql })
    });
    
    res.status(500).json({ 
      message: 'Server error during web lab creation',
      error: error.message,
      ...(process.env.NODE_ENV === 'development' && { 
        details: error.errors?.map(e => e.message) || error.parent?.message 
      })
    });
  }
};

// Update a web lab (admin only)
exports.updateWebLab = async (req, res) => {
  const transaction = await sequelize.transaction();
  
  try {
    const { id } = req.params;
    const { 
      name, 
      description, 
      category, 
      difficulty, 
      instructions, 
      htmlContent, 
      validationType, 
      validationValue, 
      allowedOrigins = [],
      points,
      hostedUrl
    } = req.body;

    // Find the lab
    const lab = await Lab.findByPk(id, {
      include: [{ model: WebLab, as: 'webLabData' }],
      transaction
    });

    if (!lab) {
      await transaction.rollback();
      return res.status(404).json({ message: 'Lab not found' });
    }

    if (lab.labType !== 'web') {
      await transaction.rollback();
      return res.status(400).json({ message: 'Not a web lab' });
    }

    // Update the base lab
    await lab.update({
      name,
      description,
      category,
      difficulty,
      instructions,
      points: points ? parseInt(points) : lab.points
    }, { transaction });

    // Update the web lab specific data
    await lab.webLabData.update({
      htmlContent: htmlContent || lab.webLabData.htmlContent,
      validationType,
      validationValue,
      hostedUrl,
      allowedOrigins: Array.isArray(allowedOrigins) ? allowedOrigins.join(',') : (allowedOrigins || '')
    }, { transaction });

    await transaction.commit();
    
    res.json({
      ...lab.toJSON(),
      webLab: lab.webLabData.toJSON()
    });
  } catch (error) {
    await transaction.rollback();
    console.error('Error updating web lab:', {
      message: error.message,
      name: error.name,
      stack: error.stack,
      ...(error.errors && { errors: error.errors.map(e => e.message) }),
      ...(error.parent && { sqlError: error.parent.message, sql: error.parent.sql })
    });
    
    res.status(500).json({ 
      message: 'Failed to update web lab',
      error: error.message,
      ...(process.env.NODE_ENV === 'development' && { 
        details: error.errors?.map(e => e.message) || error.parent?.message 
      })
    });
  }
};

// Get web lab by ID
exports.getWebLab = async (req, res) => {
  try {
    const { id } = req.params;
    
    const lab = await Lab.findOne({
      where: { id, labType: 'web' },
      include: [
        { model: WebLab, as: 'webLabData' },
        { 
          model: User, 
          as: 'assignedUsers',
          attributes: ['id', 'username', 'email'],
          through: { attributes: [] },
          where: req.user.role === 'student' ? { id: req.user.id } : undefined,
          required: req.user.role === 'student'
        }
      ]
    });

    if (!lab) {
      return res.status(404).json({ message: 'Web lab not found or not assigned to user' });
    }

    // For students, check if they have already completed this lab
    if (req.user.role === 'student') {
      const existingCompletion = await WebLabCompletion.findOne({
        where: {
          userId: req.user.id,
          labId: lab.id
        }
      });

      lab.dataValues.completed = !!existingCompletion;
    }

    res.json(lab);
  } catch (error) {
    console.error('Error getting web lab:', error);
    res.status(500).json({ 
      message: 'Server error while fetching web lab',
      error: error.message
    });
  }
};

// Submit web lab solution
exports.submitWebLab = async (req, res) => {
  const transaction = await sequelize.transaction();
  
  try {
    const { id } = req.params;
    const { flag, headers = {} } = req.body;
    const userId = req.user.id;

    // Find the lab with its web lab data
    const lab = await Lab.findOne({
      where: { id, labType: 'web' },
      include: [{ model: WebLab, as: 'webLabData' }],
      transaction
    });

    if (!lab) {
      await transaction.rollback();
      return res.status(404).json({ message: 'Web lab not found' });
    }

    // Check if user is assigned to this lab
    const isAssigned = await lab.hasAssignedUsers(userId, { transaction });
    if (!isAssigned && req.user.role !== 'admin') {
      await transaction.rollback();
      return res.status(403).json({ message: 'You are not assigned to this lab' });
    }

    // Check if user has already completed this lab
    const existingSubmission = await FlagSubmission.findOne({
      where: {
        userId,
        labId: id,
        isCorrect: true
      },
      transaction
    });

    if (existingSubmission) {
      await transaction.rollback();
      return res.status(400).json({ 
        message: 'You have already completed this lab',
        completed: true,
        submission: existingSubmission
      });
    }

    // Validate the submission based on validation type
    let isCorrect = false;
    let submissionData = {
      userId,
      labId: id,
      labType: 'web',
      validationType: lab.webLabData.validationType,
      httpHeaders: headers,
      submittedFlag: flag || null,
      isCorrect: false,
      pointsAwarded: 0,
      ipAddress: req.ip
    };

    if (lab.webLabData.validationType === 'header_check') {
      // Check if the required header is present and matches
      const [headerName, expectedValue] = lab.webLabData.validationValue.split(':');
      const headerValue = headers[headerName.trim()];
      
      isCorrect = headerValue && headerValue.trim() === expectedValue.trim();
      submissionData.isCorrect = isCorrect;
      
    } else if (lab.webLabData.validationType === 'input_flag') {
      // Check if the submitted flag matches
      isCorrect = flag === lab.webLabData.validationValue;
      submissionData.isCorrect = isCorrect;
      submissionData.submittedFlag = flag;
    } else if (lab.webLabData.validationType === 'callback') {
      // For callback validation, the isCorrect flag is set by the callback endpoint
      // This submission endpoint can still be used to manually mark as complete
      if (req.user.role === 'admin') {
        isCorrect = true;
        submissionData.isCorrect = true;
        submissionData.submittedFlag = 'Admin override';
      }
    }

    // If correct, award points
    if (isCorrect) {
      submissionData.pointsAwarded = lab.points;
      
      // Update user's points
      await User.increment('totalPoints', {
        by: lab.points,
        where: { id: userId },
        transaction
      });
      
      // Create completion record
      await WebLabCompletion.create({
        userId,
        labId: id,
        completedAt: new Date()
      }, { transaction });
    }

    // Save the submission
    const submission = await FlagSubmission.create(submissionData, { transaction });
    
    await transaction.commit();
    
    res.json({
      success: isCorrect,
      message: isCorrect 
        ? 'Congratulations! You have successfully completed the lab.' 
        : 'Incorrect solution. Please try again.',
      submission
    });

  } catch (error) {
    await transaction.rollback();
    console.error('Error submitting web lab solution:', error);
    res.status(500).json({ 
      message: 'Server error while processing your submission',
      error: error.message
    });
  }
};

// Get web lab submissions (admin only)
exports.getWebLabSubmissions = async (req, res) => {
  try {
    const { id } = req.params;
    
    const submissions = await FlagSubmission.findAll({
      where: { 
        labId: id,
        labType: 'web' 
      },
      include: [
        {
          model: User,
          attributes: ['id', 'username', 'email']
        }
      ],
      order: [['submissionTime', 'DESC']]
    });

    res.json(submissions);
  } catch (error) {
    console.error('Error getting web lab submissions:', error);
    res.status(500).json({ 
      message: 'Server error while fetching submissions',
      error: error.message
    });
  }
};

// Get all web labs (admin only)
exports.getAllWebLabs = async (req, res) => {
  try {
    const labs = await Lab.findAll({
      where: { labType: 'web' },
      include: [
        {
          model: WebLab,
          as: 'webLabData'
        },
        {
          model: User,
          as: 'creator',
          attributes: ['id', 'username', 'email']
        }
      ],
      order: [['createdAt', 'DESC']]
    });

    res.json(labs);
  } catch (error) {
    console.error('Error getting web labs:', error);
    res.status(500).json({ 
      message: 'Server error while fetching web labs',
      error: error.message
    });
  }
};

// Status check endpoint for header-based validation
exports.statusCheck = async (req, res) => {
  try {
    const { id } = req.params;
    
    const lab = await Lab.findOne({
      where: { id, labType: 'web' },
      include: [{ model: WebLab, as: 'webLabData' }]
    });

    if (!lab) {
      return res.status(404).json({ message: 'Web lab not found' });
    }

    // For external web labs, redirect to the hosted URL
    if (lab.webLabData.hostedUrl) {
      let redirectUrl = lab.webLabData.hostedUrl;
      // Replace any placeholders in the URL
      redirectUrl = redirectUrl.replace(/{{LAB_ID}}/g, id);
      return res.redirect(redirectUrl);
    }

    // For inline HTML web labs, serve the HTML content
    let htmlContent = lab.webLabData.htmlContent;
    htmlContent = htmlContent.replace(/{{LAB_ID}}/g, id);

    // Set appropriate headers based on lab configuration
    if (lab.webLabData.validationType === 'header_check') {
      // This endpoint is used by the iframe to check completion status
      // The actual completion check happens in the submit endpoint
      res.set('Lab-Status', 'In Progress');
    }

    res.send(htmlContent);
  } catch (error) {
    console.error('Error in status check:', error);
    res.status(500).json({ 
      message: 'Server error while checking status',
      error: error.message
    });
  }
};

// Check lab completion status
exports.checkLabStatus = async (req, res) => {
  try {
    const { id } = req.params;
    const userId = req.user.id;

    // Find the lab with its web lab data
    const lab = await Lab.findOne({
      where: { id, labType: 'web' },
      include: [{ model: WebLab, as: 'webLabData' }]
    });

    if (!lab) {
      return res.status(404).json({ message: 'Web lab not found' });
    }

    // Check if user has already completed this lab
    const existingCompletion = await WebLabCompletion.findOne({
      where: {
        userId,
        labId: id
      }
    });

    if (existingCompletion) {
      return res.json({ completed: true, completedAt: existingCompletion.completedAt });
    }

    // If validation type is header_check and there's a hosted URL, check the headers
    if (lab.webLabData.validationType === 'header_check' && lab.webLabData.hostedUrl) {
      try {
        // Make a request to the hosted URL to check headers
        const fetch = require('node-fetch');
        const response = await fetch(lab.webLabData.hostedUrl.replace(/{{LAB_ID}}/g, id), {
          method: 'HEAD',
          headers: {
            'User-Agent': 'CyberRangeStatusCheck/1.0'
          }
        });

        // Check if the required header is present and matches
        const [headerName, expectedValue] = lab.webLabData.validationValue.split(':');
        const headerValue = response.headers.get(headerName.trim());

        if (headerValue && headerValue.trim() === expectedValue.trim()) {
          // Create completion record
          await WebLabCompletion.create({
            userId,
            labId: id,
            completedAt: new Date()
          });

          // Update user's points
          await User.increment('totalPoints', {
            by: lab.points,
            where: { id: userId }
          });

          return res.json({ completed: true, completedAt: new Date() });
        }
      } catch (fetchError) {
        console.error('Error checking external lab status:', fetchError);
        // Continue to return not completed if fetch fails
      }
    }

    // If we get here, the lab is not completed
    res.json({ completed: false });
  } catch (error) {
    console.error('Error checking lab status:', error);
    res.status(500).json({ 
      message: 'Server error while checking lab status',
      error: error.message
    });
  }
};

// Callback endpoint for external labs to mark completion
exports.completeLabCallback = async (req, res) => {
  console.log('Lab completion callback received:', {
    labId: req.params.id,
    body: req.body,
    headers: {
      authorization: req.headers.authorization ? 'present' : 'missing',
      'x-auth-token': req.headers['x-auth-token'] ? 'present' : 'missing'
    },
    userPresent: req.user ? 'yes' : 'no'
  });
  
  try {
    const { id } = req.params;
    let userId;
    
    // Check if we have a user in the request (from auth middleware)
    if (req.user && req.user.id) {
      userId = req.user.id;
      console.log('User ID from request:', userId);
    } else {
      // If no user in request, try to extract token from Authorization header or x-auth-token header
      const token = req.headers['x-auth-token'] || 
                   (req.headers.authorization ? req.headers.authorization.replace('Bearer ', '') : null);
      
      console.log('Token extraction attempt:', token ? 'token found' : 'no token');
      
      if (!token) {
        console.log('Authentication failed: No token provided');
        return res.status(401).json({ message: 'No authentication token provided' });
      }
      
      try {
        // Verify and decode the token
        const jwt = require('jsonwebtoken');
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        userId = decoded.id;
        
        console.log('Token decoded successfully, user ID:', userId);
        
        if (!userId) {
          console.log('Authentication failed: Token decoded but no user ID found');
          return res.status(401).json({ message: 'Invalid token - no user ID' });
        }
      } catch (tokenError) {
        console.error('Token verification error:', tokenError);
        return res.status(401).json({ message: 'Invalid authentication token' });
      }
    }

    // Find the lab with its web lab data
    const lab = await Lab.findOne({
      where: { id, labType: 'web' },
      include: [{ model: WebLab, as: 'webLabData' }]
    });

    if (!lab) {
      return res.status(404).json({ message: 'Web lab not found' });
    }

    // Verify this lab uses callback validation
    if (lab.webLabData.validationType !== 'callback') {
      return res.status(400).json({ message: 'This lab does not use callback validation' });
    }

    // Check if user has already completed this lab
    const existingCompletion = await WebLabCompletion.findOne({
      where: {
        userId,
        labId: id
      }
    });

    if (existingCompletion) {
      return res.json({ 
        message: 'Lab already completed',
        completed: true, 
        completedAt: existingCompletion.completedAt 
      });
    }

    // Create completion record
    const completion = await WebLabCompletion.create({
      userId,
      labId: id,
      completedAt: new Date()
    });

    // Update user's points
    await User.increment('totalPoints', {
      by: lab.points,
      where: { id: userId }
    });

    // Create a flag submission record for tracking
    await FlagSubmission.create({
      userId,
      labId: id,
      labType: 'web',
      validationType: 'callback',
      submittedFlag: 'Callback completion',
      isCorrect: true,
      pointsAwarded: lab.points,
      ipAddress: req.ip
    });

    res.json({ 
      message: 'Lab completed successfully',
      completed: true, 
      completedAt: completion.completedAt,
      pointsAwarded: lab.points
    });
  } catch (error) {
    console.error('Error in lab completion callback:', error);
    res.status(500).json({ 
      message: 'Server error while processing lab completion',
      error: error.message
    });
  }
};

// Delete a web lab (admin only)
exports.deleteWebLab = async (req, res) => {
  const transaction = await sequelize.transaction();
  
  try {
    const { id } = req.params;

    const lab = await Lab.findOne({
      where: { id, labType: 'web' },
      include: [{ model: WebLab, as: 'webLabData' }],
      transaction
    });

    if (!lab) {
      await transaction.rollback();
      return res.status(404).json({ message: 'Web lab not found' });
    }

    // Delete associated WebLab data (this will cascade)
    await WebLab.destroy({ 
      where: { labId: id },
      transaction 
    });

    // Delete the lab itself
    await Lab.destroy({ 
      where: { id },
      transaction 
    });

    await transaction.commit();
    
    res.json({ message: 'Web lab deleted successfully' });
  } catch (error) {
    await transaction.rollback();
    console.error('Error deleting web lab:', error);
    res.status(500).json({ 
      message: 'Server error while deleting web lab',
      error: error.message
    });
  }
};

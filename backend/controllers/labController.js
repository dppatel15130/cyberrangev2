const { Lab, User, sequelize } = require('../models');
const { Op, fn, col } = require('sequelize');
const loggers = require('../config/logger');

// Create a new lab (admin only)
exports.createLab = async (req, res) => {
  try {
    loggers.logLab('CREATE_ATTEMPT', null, req.user.id, {
      name: req.body.name,
      labType: req.body.labType || 'vm',
      category: req.body.category
    });

    console.log('Creating lab with data:', req.body);
    const { 
      name, 
      description, 
      category, 
      difficulty, 
      instructions, 
      flag, 
      vmTemplateId,
      duration = 60,
      points = 100,
      status = 'draft',
      tags = [],
      labType = 'vm',
      targetUrl
    } = req.body;

    // Validate required fields based on lab type
    if (labType === 'vm' && !vmTemplateId) {
      loggers.logLab('CREATE_FAILED', null, req.user.id, {
        reason: 'VM Template ID required',
        name
      });
      return res.status(400).json({ message: 'VM Template ID is required for VM labs' });
    }
    
    if (labType === 'web' && !targetUrl) {
      loggers.logLab('CREATE_FAILED', null, req.user.id, {
        reason: 'Target URL required',
        name
      });
      return res.status(400).json({ message: 'Target URL is required for web labs' });
    }

    // Validate flag format if provided
    if (flag && !flag.startsWith('flag{')) {
      loggers.logLab('CREATE_FAILED', null, req.user.id, {
        reason: 'Invalid flag format',
        name
      });
      return res.status(400).json({ message: 'Flag must start with "flag{"' });
    }

    // Check if lab name already exists
    const existingLab = await Lab.findOne({ where: { name } });
    if (existingLab) {
      loggers.logLab('CREATE_FAILED', null, req.user.id, {
        reason: 'Lab name already exists',
        name
      });
      return res.status(400).json({ message: 'Lab name already exists. Please choose a different name.' });
    }

    const lab = await Lab.create({
      name,
      description,
      category,
      difficulty,
      instructions,
      flag,
      vmTemplateId,
      targetUrl,
      labType,
      duration: parseInt(duration) || 60,
      points: parseInt(points) || 100,
      status,
      tags: Array.isArray(tags) ? tags : [],
      createdBy: req.user.id,
      isActive: status === 'active',
      lastModified: new Date()
    });

    loggers.logLab('CREATE_SUCCESS', lab.id, req.user.id, {
      name: lab.name,
      labType: lab.labType,
      category: lab.category,
      difficulty: lab.difficulty,
      status: lab.status
    });

    loggers.logDatabase('CREATE', 'labs', {
      labId: lab.id,
      name: lab.name,
      createdBy: req.user.id
    });

    console.log('Lab created successfully:', lab.toJSON());
    res.status(201).json({
      ...lab.toJSON(),
      message: status === 'draft' ? 'Lab saved as draft' : 'Lab created successfully'
    });
  } catch (error) {
    loggers.logError(error, req, {
      operation: 'LAB_CREATION',
      labName: req.body.name
    });
    console.error('Create lab error:', error);
    
    // Handle Sequelize validation errors
    if (error.name === 'SequelizeValidationError') {
      const validationErrors = error.errors.map(err => ({
        field: err.path,
        message: err.message
      }));
      return res.status(400).json({ 
        message: 'Validation errors',
        errors: validationErrors
      });
    }
    
    res.status(500).json({ 
      message: 'Server error during lab creation',
      error: error.message,
      stack: process.env.NODE_ENV === 'development' ? error.stack : undefined
    });
  }
};

// Get all labs
exports.getAllLabs = async (req, res) => {
  console.log('=== START: getAllLabs ===');
  try {
    console.log('User making request:', {
      id: req.user?.id,
      role: req.user?.role,
      email: req.user?.email
    });
    
    let labs;
    
    // If admin, get all labs with assigned users count
    if (req.user?.role === 'admin') {
      console.log('Admin user detected, fetching all labs with assigned users count');
      
      // Get all labs with their creator and assigned users
      const allLabs = await Lab.findAll({
        include: [
          {
            model: User,
            as: 'creator',
            attributes: ['username']
          },
          {
            model: User,
            as: 'assignedUsers',
            attributes: ['id', 'username', 'email'],
            through: { attributes: [] } // Don't include join table attributes
          }
        ]
      });

      // Convert to plain objects and add assignedUsersCount
      labs = allLabs.map(lab => {
        const labData = lab.get({ plain: true });
        return {
          ...labData,
          assignedUsersCount: labData.assignedUsers?.length || 0
        };
      });
    } else {
      // For regular users, only get labs assigned to them
      const user = await User.findByPk(req.user.id, {
        include: [{
          model: Lab,
          as: 'assignedLabs',
          through: { attributes: [] },
          include: [{
            model: User,
            as: 'creator',
            attributes: ['username']
          }]
        }]
      });
      labs = user.assignedLabs;
    }

    console.log('Successfully retrieved labs:', labs.length, 'labs found');
    res.json(labs);
  } catch (error) {
    console.error('=== ERROR in getAllLabs ===');
    console.error('Error details:', {
      name: error.name,
      message: error.message,
      stack: error.stack,
      additionalInfo: {
        isSequelizeError: error.name?.includes('Sequelize'),
        isValidationError: error.name === 'SequelizeValidationError',
        isDatabaseError: error.name === 'SequelizeDatabaseError',
        isConnectionError: error.name === 'SequelizeConnectionError'
      }
    });
    
    if (error.errors) {
      console.error('Validation errors:', error.errors.map(e => ({
        path: e.path,
        message: e.message,
        type: e.type,
        value: e.value
      })));
    }
    
    res.status(500).json({ 
      message: 'Server error while fetching labs',
      error: process.env.NODE_ENV === 'development' ? {
        name: error.name,
        message: error.message,
        ...(error.errors && { errors: error.errors })
      } : undefined
    });
  } finally {
    console.log('=== END: getAllLabs ===');
  }
};

// Get lab by ID
exports.getLabById = async (req, res) => {
  try {
    console.log('Fetching lab with ID:', req.params.id);
    const lab = await Lab.findByPk(req.params.id, {
      include: [{
        model: User,
        as: 'creator',
        attributes: ['id', 'username', 'email']
      }],
      attributes: {
        include: [
          'id', 'name', 'description', 'category', 'difficulty', 
          'instructions', 'flag', 'vmTemplateId', 'duration', 
          'createdAt', 'updatedAt', 'createdBy'
        ]
      }
    });
    
    if (!lab) {
      console.log('Lab not found with ID:', req.params.id);
      return res.status(404).json({ message: 'Lab not found' });
    }

    // Check if user is admin or the lab is assigned to them
    if (req.user.role !== 'admin') {
      console.log('Checking user access for lab:', req.user.id);
      const user = await User.findByPk(req.user.id, {
        include: [{
          model: Lab,
          as: 'assignedLabs',
          where: { id: req.params.id },
          attributes: ['id']
        }]
      });
      
      if (!user || !user.assignedLabs || user.assignedLabs.length === 0) {
        console.log('User not authorized to access lab:', req.user.id);
        return res.status(403).json({ message: 'Not authorized to access this lab' });
      }
    }

    const labData = lab.get({ plain: true });
    console.log('Sending lab data:', {
      id: labData.id,
      name: labData.name,
      hasCreator: !!labData.creator,
      duration: labData.duration,
      rawData: JSON.stringify(labData, null, 2).substring(0, 500) + '...' // First 500 chars of raw data
    });
    
    res.json(labData);
  } catch (error) {
    console.error('Get lab by ID error:', error);
    res.status(500).json({ message: 'Server error' });
  }
};

// Update lab (admin only)
exports.updateLab = async (req, res) => {
  try {
    const { 
      name, 
      description, 
      category, 
      difficulty, 
      instructions, 
      flag, 
      vmTemplateId, 
      duration, 
      points,
      active, 
      status,
      tags,
      labType,
      targetUrl
    } = req.body;

    const lab = await Lab.findByPk(req.params.id);
    if (!lab) {
      return res.status(404).json({ message: 'Lab not found' });
    }

    // Validate lab name uniqueness (excluding current lab)
    if (name && name !== lab.name) {
      const existingLab = await Lab.findOne({ 
        where: { 
          name,
          id: { [Op.ne]: req.params.id }
        } 
      });
      if (existingLab) {
        return res.status(400).json({ message: 'Lab name already exists. Please choose a different name.' });
      }
    }

    // Validate required fields based on lab type
    const currentLabType = labType || lab.labType;
    if (currentLabType === 'vm' && !vmTemplateId && !lab.vmTemplateId) {
      return res.status(400).json({ message: 'VM Template ID is required for VM labs' });
    }
    
    if (currentLabType === 'web' && !targetUrl && !lab.targetUrl) {
      return res.status(400).json({ message: 'Target URL is required for web labs' });
    }

    // Validate flag format if provided
    if (flag && !flag.startsWith('flag{')) {
      return res.status(400).json({ message: 'Flag must start with "flag{"' });
    }

    // Prepare update data
    const updateData = {
      lastModified: new Date()
    };

    // Only update fields that are provided
    if (name !== undefined) updateData.name = name;
    if (description !== undefined) updateData.description = description;
    if (category !== undefined) updateData.category = category;
    if (difficulty !== undefined) updateData.difficulty = difficulty;
    if (instructions !== undefined) updateData.instructions = instructions;
    if (flag !== undefined) updateData.flag = flag;
    if (vmTemplateId !== undefined) updateData.vmTemplateId = vmTemplateId;
    if (targetUrl !== undefined) updateData.targetUrl = targetUrl;
    if (labType !== undefined) updateData.labType = labType;
    if (duration !== undefined) updateData.duration = parseInt(duration) || 60;
    if (points !== undefined) updateData.points = parseInt(points) || 100;
    if (status !== undefined) {
      updateData.status = status;
      updateData.isActive = status === 'active';
    } else if (active !== undefined) {
      updateData.isActive = active;
      // Update status based on active flag if status not explicitly provided
      updateData.status = active ? 'active' : 'inactive';
    }
    if (tags !== undefined) updateData.tags = Array.isArray(tags) ? tags : [];

    await lab.update(updateData);

    // Fetch updated lab with creator info
    const updatedLab = await Lab.findByPk(req.params.id, {
      include: [{
        model: User,
        as: 'creator',
        attributes: ['id', 'username', 'email']
      }]
    });

    res.json({
      ...updatedLab.toJSON(),
      message: 'Lab updated successfully'
    });
  } catch (error) {
    console.error('Update lab error:', error);
    
    // Handle Sequelize validation errors
    if (error.name === 'SequelizeValidationError') {
      const validationErrors = error.errors.map(err => ({
        field: err.path,
        message: err.message
      }));
      return res.status(400).json({ 
        message: 'Validation errors',
        errors: validationErrors
      });
    }
    
    res.status(500).json({ 
      message: 'Server error during lab update',
      error: error.message
    });
  }
};

// Delete lab (admin only)
exports.deleteLab = async (req, res) => {
  try {
    const lab = await Lab.findByPk(req.params.id);

    if (!lab) {
      return res.status(404).json({ message: 'Lab not found' });
    }

    // Remove lab from all users' assignedLabs (through junction table)
    await lab.removeAssignedUsers(await lab.getAssignedUsers());

    await lab.destroy();

    res.json({ message: 'Lab deleted successfully' });
  } catch (error) {
    console.error('Delete lab error:', error);
    res.status(500).json({ message: 'Server error' });
  }
};

// Assign lab to users (admin only)
exports.assignLab = async (req, res) => {
  try {
    const { labId, userIds } = req.body;
    console.log('AssignLab called with:', { labId, userIds });

    const lab = await Lab.findByPk(labId);
    if (!lab) return res.status(404).json({ message: 'Lab not found' });

    const users = await User.findAll({ where: { id: { [Op.in]: userIds } } });
    console.log('Users found for assignment:', users.map(u => u.id));

    await lab.addAssignedUsers(users); // This should persist in UserLabs

    // Debug: Check UserLabs table after assignment
    const [results] = await require('../config/db').sequelize.query('SELECT * FROM UserLabs');
    console.log('UserLabs table after assignment:', results);

    res.json({ message: 'Lab assigned successfully' });
  } catch (error) {
    console.error('Assign lab error:', error);
    res.status(500).json({ message: 'Server error' });
  }
};

// Unassign lab from users (admin only)
exports.unassignLab = async (req, res) => {
  try {
    const { labId, userIds } = req.body;

    // Verify lab exists
    const lab = await Lab.findByPk(labId);
    if (!lab) {
      return res.status(404).json({ message: 'Lab not found' });
    }

    // Get users to unassign
    const users = await User.findAll({
      where: {
        id: {
          [Op.in]: userIds
        }
      }
    });

    // Unassign lab from users
    await lab.removeAssignedUsers(users);

    res.json({ message: 'Lab unassigned successfully' });
  } catch (error) {
    console.error('Unassign lab error:', error);
    res.status(500).json({ message: 'Server error' });
  }
};

// Save lab as draft (admin only)
exports.saveDraft = async (req, res) => {
  try {
    const labData = {
      ...req.body,
      status: 'draft',
      isActive: false,
      createdBy: req.user.id,
      lastModified: new Date()
    };

    let lab;
    if (req.params.id) {
      // Update existing draft
      lab = await Lab.findByPk(req.params.id);
      if (!lab) {
        return res.status(404).json({ message: 'Lab not found' });
      }
      
      // Ensure only drafts can be updated this way
      if (lab.status !== 'draft') {
        return res.status(400).json({ message: 'Can only save drafts of labs that are currently in draft status' });
      }
      
      await lab.update(labData);
    } else {
      // Create new draft
      lab = await Lab.create(labData);
    }

    res.status(201).json({
      ...lab.toJSON(),
      message: 'Lab saved as draft successfully'
    });
  } catch (error) {
    console.error('Save draft error:', error);
    
    if (error.name === 'SequelizeValidationError') {
      const validationErrors = error.errors.map(err => ({
        field: err.path,
        message: err.message
      }));
      return res.status(400).json({ 
        message: 'Validation errors',
        errors: validationErrors
      });
    }
    
    res.status(500).json({ 
      message: 'Server error during draft save',
      error: error.message
    });
  }
};

// Publish lab from draft (admin only)
exports.publishLab = async (req, res) => {
  try {
    const lab = await Lab.findByPk(req.params.id);
    if (!lab) {
      return res.status(404).json({ message: 'Lab not found' });
    }

    // Validate that all required fields are present for publishing
    const requiredFields = ['name', 'description', 'category', 'instructions'];
    const missingFields = requiredFields.filter(field => !lab[field]);
    
    if (missingFields.length > 0) {
      return res.status(400).json({ 
        message: 'Missing required fields for publishing',
        missingFields
      });
    }

    // Additional validation based on lab type
    if (lab.labType === 'vm' && !lab.vmTemplateId) {
      return res.status(400).json({ message: 'VM Template ID is required for VM labs' });
    }
    
    if (lab.labType === 'web' && !lab.targetUrl) {
      return res.status(400).json({ message: 'Target URL is required for web labs' });
    }

    await lab.update({
      status: 'active',
      isActive: true,
      lastModified: new Date()
    });

    res.json({
      ...lab.toJSON(),
      message: 'Lab published successfully'
    });
  } catch (error) {
    console.error('Publish lab error:', error);
    res.status(500).json({ 
      message: 'Server error during lab publishing',
      error: error.message
    });
  }
};

// Archive lab (admin only)
exports.archiveLab = async (req, res) => {
  try {
    const lab = await Lab.findByPk(req.params.id);
    if (!lab) {
      return res.status(404).json({ message: 'Lab not found' });
    }

    await lab.update({
      status: 'archived',
      isActive: false,
      lastModified: new Date()
    });

    res.json({
      ...lab.toJSON(),
      message: 'Lab archived successfully'
    });
  } catch (error) {
    console.error('Archive lab error:', error);
    res.status(500).json({ 
      message: 'Server error during lab archiving',
      error: error.message
    });
  }
};

// Get lab statistics (admin only)
exports.getLabStatistics = async (req, res) => {
  try {
    const stats = await Lab.findAll({
      attributes: [
        'status',
        [fn('COUNT', col('id')), 'count']
      ],
      group: ['status']
    });

    const totalLabs = await Lab.count();
    const activeLabs = await Lab.count({ where: { status: 'active' } });
    const draftLabs = await Lab.count({ where: { status: 'draft' } });
    const archivedLabs = await Lab.count({ where: { status: 'archived' } });

    res.json({
      total: totalLabs,
      active: activeLabs,
      draft: draftLabs,
      archived: archivedLabs,
      byStatus: stats.map(stat => ({
        status: stat.status,
        count: parseInt(stat.get('count'))
      }))
    });
  } catch (error) {
    console.error('Get lab statistics error:', error);
    res.status(500).json({ 
      message: 'Server error while fetching statistics',
      error: error.message
    });
  }
};

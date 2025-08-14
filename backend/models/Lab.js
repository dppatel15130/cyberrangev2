const { DataTypes } = require('sequelize');
const { sequelize } = require('../config/db');

const Lab = sequelize.define('Lab', {
  id: {
    type: DataTypes.INTEGER,
    primaryKey: true,
    autoIncrement: true
  },
  name: {
    type: DataTypes.STRING,
    allowNull: false,
    validate: {
      notEmpty: true
    }
  },
  description: {
    type: DataTypes.TEXT,
    allowNull: false
  },
  category: {
    type: DataTypes.STRING,
    allowNull: false,
    validate: {
      notEmpty: true
    }
  },
  difficulty: {
    type: DataTypes.ENUM('beginner', 'intermediate', 'advanced'),
    defaultValue: 'intermediate',
    allowNull: false
  },
  instructions: {
    type: DataTypes.TEXT,
    allowNull: false
  },
  flag: {
    type: DataTypes.STRING,
    allowNull: true // Make flag optional for special labs
  },
  labType: {
    type: DataTypes.ENUM('vm', 'special', 'web'),
    defaultValue: 'vm',
    allowNull: false,
    validate: {
      isIn: {
        args: [['vm', 'special', 'web']],
        msg: 'Lab type must be either vm, special, or web'
      }
    }
  },
  vmTemplateId: {
    type: DataTypes.STRING,
    allowNull: true // Make optional for special labs
  },
  targetUrl: {
    type: DataTypes.STRING,
    allowNull: true, // Only required for special labs
    validate: {
      isUrl: {
        msg: 'Must be a valid URL',
        require_protocol: true
      }
    }
  },
  createdBy: {
    type: DataTypes.INTEGER,
    allowNull: false,
    references: {
      model: 'Users',
      key: 'id'
    }
  },
  isActive: {
    type: DataTypes.BOOLEAN,
    defaultValue: true
  },

  duration: {
    type: DataTypes.INTEGER,
    allowNull: false,
    defaultValue: 60, // in minutes
    validate: {
      min: 1,
      isInt: true
    }
  },
  points: {
    type: DataTypes.INTEGER,
    allowNull: false,
    defaultValue: 100, // Default points for completing the lab
    validate: {
      min: 1,
      isInt: true
    }
  },
  status: {
    type: DataTypes.ENUM('draft', 'active', 'inactive', 'archived'),
    defaultValue: 'draft',
    allowNull: false,
    validate: {
      isIn: {
        args: [['draft', 'active', 'inactive', 'archived']],
        msg: 'Status must be draft, active, inactive, or archived'
      }
    }
  },
  lastModified: {
    type: DataTypes.DATE,
    defaultValue: DataTypes.NOW,
    allowNull: false
  },
  tags: {
    type: DataTypes.JSON,
    allowNull: true,
    defaultValue: [],
    comment: 'Array of tags for categorizing and searching labs'
  }
}, {
  timestamps: true,
  hooks: {
    beforeUpdate: (lab, options) => {
      lab.lastModified = new Date();
    }
  }
});

module.exports = Lab;
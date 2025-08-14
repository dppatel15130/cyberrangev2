const { DataTypes } = require('sequelize');
const { sequelize } = require('../config/db');

const FlagSubmission = sequelize.define('FlagSubmission', {
  id: {
    type: DataTypes.INTEGER,
    primaryKey: true,
    autoIncrement: true
  },
  userId: {
    type: DataTypes.INTEGER,
    allowNull: false,
    references: {
      model: 'Users',
      key: 'id'
    }
  },
  labId: {
    type: DataTypes.INTEGER,
    allowNull: false,
    references: {
      model: 'Labs',
      key: 'id'
    }
  },
  submittedFlag: {
    type: DataTypes.STRING,
    allowNull: true, // Can be null for web labs that use header checks
    validate: {
      notEmpty: {
        msg: 'Flag cannot be empty',
        args: function(val) {
          // Only validate if this is not a web lab submission
          return !(this.labType === 'web' && this.validationType !== 'input_flag');
        }
      }
    }
  },
  labType: {
    type: DataTypes.ENUM('vm', 'special', 'web'),
    allowNull: false,
    defaultValue: 'vm'
  },
  validationType: {
    type: DataTypes.ENUM('header_check', 'input_flag'),
    allowNull: true
  },
  httpHeaders: {
    type: DataTypes.TEXT,
    allowNull: true,
    get() {
      const headers = this.getDataValue('httpHeaders');
      return headers ? JSON.parse(headers) : null;
    },
    set(val) {
      this.setDataValue('httpHeaders', val ? JSON.stringify(val) : null);
    },
    comment: 'Stores HTTP headers for web lab validations'
  },
  isCorrect: {
    type: DataTypes.BOOLEAN,
    allowNull: false
  },
  pointsAwarded: {
    type: DataTypes.INTEGER,
    allowNull: false,
    defaultValue: 0,
    validate: {
      min: 0,
      isInt: true
    }
  },
  submissionTime: {
    type: DataTypes.DATE,
    allowNull: false,
    defaultValue: DataTypes.NOW
  },
  ipAddress: {
    type: DataTypes.STRING,
    allowNull: true // Optional: track IP for security
  },
  attemptCount: {
    type: DataTypes.INTEGER,
    allowNull: false,
    defaultValue: 1,
    validate: {
      min: 1,
      isInt: true
    }
  }
}, {
  timestamps: true,
  indexes: [
    {
      fields: ['userId']
    },
    {
      fields: ['labId']
    },
    {
      fields: ['isCorrect']
    },
    {
      fields: ['submissionTime']
    },
    {
      fields: ['userId', 'labId', 'isCorrect']
    }
  ]
});

module.exports = FlagSubmission;

const { DataTypes } = require('sequelize');
const { sequelize } = require('../config/db');
const Lab = require('./Lab');

const WebLab = sequelize.define('WebLab', {
  id: {
    type: DataTypes.INTEGER,
    primaryKey: true,
    autoIncrement: true
  },
  labId: {
    type: DataTypes.INTEGER,
    allowNull: false,
    references: {
      model: 'Labs',
      key: 'id'
    },
    onDelete: 'CASCADE',
    onUpdate: 'CASCADE'
  },
  htmlContent: {
    type: DataTypes.TEXT,
    allowNull: true,
    validate: {
      customValidator(value) {
        // Either htmlContent or hostedUrl must be provided
        if (!value && !this.hostedUrl) {
          throw new Error('Either HTML content or hosted URL must be provided');
        }
      }
    }
  },
  validationType: {
    type: DataTypes.ENUM('header_check', 'input_flag', 'callback'),
    allowNull: false,
    defaultValue: 'header_check'
  },
  hostedUrl: {
    type: DataTypes.STRING,
    allowNull: true,
    validate: {
      isValidUrl(value) {
        if (!value) return true; // Allow null/empty
        try {
          const url = new URL(value);
          // Check if protocol is http or https
          if (!['http:', 'https:'].includes(url.protocol)) {
            throw new Error('URL must use http or https protocol');
          }
          // Check if hostname is localhost or 127.0.0.1
          if (!['localhost', '127.0.0.1'].includes(url.hostname)) {
            throw new Error('Hosted URL must point to localhost or 127.0.0.1');
          }
          return true;
        } catch (e) {
          throw new Error('Must be a valid URL (e.g., http://localhost:5000/path)');
        }
      }
    }
  },
  validationValue: {
    type: DataTypes.STRING,
    allowNull: false,
    validate: {
      notEmpty: true
    }
  },
  allowedOrigins: {
    type: DataTypes.TEXT,
    allowNull: true,
    get() {
      const origins = this.getDataValue('allowedOrigins');
      return origins ? origins.split(',').map(origin => origin.trim()) : [];
    },
    set(val) {
      this.setDataValue('allowedOrigins', Array.isArray(val) ? val.join(',') : val);
    }
  }
}, {
  timestamps: true,
  indexes: [
    {
      unique: true,
      fields: ['labId']
    }
  ]
});

// Define associations
WebLab.belongsTo(Lab, {
  foreignKey: 'labId',
  as: 'lab',
  onDelete: 'CASCADE'
});

Lab.hasOne(WebLab, {
  foreignKey: 'labId',
  as: 'webLab',
  onDelete: 'CASCADE'
});

module.exports = WebLab;

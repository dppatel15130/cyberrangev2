const { DataTypes } = require('sequelize');
const { sequelize } = require('../config/db');

const WebLabCompletion = sequelize.define('WebLabCompletion', {
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
  completedAt: {
    type: DataTypes.DATE,
    allowNull: false,
    defaultValue: DataTypes.NOW
  }
}, {
  timestamps: true,
  indexes: [
    {
      unique: true,
      fields: ['userId', 'labId']
    },
    {
      fields: ['userId']
    },
    {
      fields: ['labId']
    },
    {
      fields: ['completedAt']
    }
  ]
});

module.exports = WebLabCompletion;

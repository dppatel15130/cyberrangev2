const { DataTypes } = require('sequelize');
const { sequelize } = require('../config/db');

const VM = sequelize.define('VM', {
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
  vmId: {
    type: DataTypes.STRING,
    allowNull: false
  },
  ipAddress: {
    type: DataTypes.STRING,
    allowNull: true
  },
  guacamoleConnectionId: {
    type: DataTypes.STRING,
    allowNull: true
  },
  status: {
    type: DataTypes.ENUM('creating', 'running', 'stopped', 'error'),
    defaultValue: 'creating',
    allowNull: false
  },
  startTime: {
    type: DataTypes.DATE,
    defaultValue: DataTypes.NOW
  },
  endTime: {
    type: DataTypes.DATE,
    allowNull: true
  },
  preWarmed: {
    type: DataTypes.BOOLEAN,
    allowNull: false,
    defaultValue: false
  }
}, {
  timestamps: true
});

module.exports = VM;
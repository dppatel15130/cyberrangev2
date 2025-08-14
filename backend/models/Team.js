const { DataTypes } = require('sequelize');
const { sequelize } = require('../config/db');

const Team = sequelize.define('Team', {
  id: {
    type: DataTypes.INTEGER,
    primaryKey: true,
    autoIncrement: true
  },
  name: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true,
    validate: {
      len: [2, 50],
      notEmpty: true,
      isAlphanumeric: false, // Allow spaces and special chars for team names
      is: /^[a-zA-Z0-9\s\-_]+$/ // Letters, numbers, spaces, hyphens, underscores
    }
  },
  description: {
    type: DataTypes.TEXT,
    allowNull: true
  },
  color: {
    type: DataTypes.STRING(7),
    allowNull: false,
    defaultValue: '#FF0000',
    validate: {
      is: /^#[0-9A-F]{6}$/i // Valid hex color
    },
    comment: 'Team color for UI display (hex format)'
  },
  maxMembers: {
    type: DataTypes.INTEGER,
    allowNull: false,
    defaultValue: 4,
    validate: {
      min: 1,
      max: 10,
      isInt: true
    }
  },
  currentPoints: {
    type: DataTypes.INTEGER,
    allowNull: false,
    defaultValue: 0,
    validate: {
      min: 0,
      isInt: true
    }
  },
  totalFlags: {
    type: DataTypes.INTEGER,
    allowNull: false,
    defaultValue: 0,
    validate: {
      min: 0,
      isInt: true
    }
  },
  isActive: {
    type: DataTypes.BOOLEAN,
    allowNull: false,
    defaultValue: true
  },
  createdBy: {
    type: DataTypes.INTEGER,
    allowNull: false,
    references: {
      model: 'Users',
      key: 'id'
    }
  },
  // Air-gapped specific fields
  assignedVMs: {
    type: DataTypes.JSON,
    allowNull: true,
    comment: 'Array of VM IDs assigned to this team',
    get() {
      const vms = this.getDataValue('assignedVMs');
      return vms ? JSON.parse(vms) : [];
    },
    set(val) {
      this.setDataValue('assignedVMs', val ? JSON.stringify(val) : null);
    }
  },
  networkSegment: {
    type: DataTypes.STRING,
    allowNull: true,
    comment: 'Network segment assigned to team (e.g., 172.16.200.0/28)'
  },
  lastActivity: {
    type: DataTypes.DATE,
    allowNull: true,
    defaultValue: DataTypes.NOW
  }
}, {
  timestamps: true,
  indexes: [
    {
      fields: ['name'],
      unique: true
    },
    {
      fields: ['currentPoints'],
      name: 'idx_team_points'
    },
    {
      fields: ['isActive']
    },
    {
      fields: ['createdBy']
    },
    {
      fields: ['lastActivity']
    }
  ],
  hooks: {
    beforeValidate: (team, options) => {
      if (team.name) {
        team.name = team.name.trim();
      }
    },
    afterUpdate: (team, options) => {
      team.lastActivity = new Date();
    }
  }
});

module.exports = Team;

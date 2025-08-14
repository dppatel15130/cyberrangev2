const { DataTypes } = require('sequelize');
const { sequelize } = require('../config/db');

const Match = sequelize.define('Match', {
  id: {
    type: DataTypes.INTEGER,
    primaryKey: true,
    autoIncrement: true
  },
  name: {
    type: DataTypes.STRING,
    allowNull: false,
    validate: {
      len: [3, 100],
      notEmpty: true
    }
  },
  description: {
    type: DataTypes.TEXT,
    allowNull: true
  },
  status: {
    type: DataTypes.ENUM('setup', 'waiting', 'active', 'paused', 'finished', 'cancelled'),
    allowNull: false,
    defaultValue: 'setup'
  },
  matchType: {
    type: DataTypes.ENUM('attack_defend', 'capture_flag', 'red_vs_blue', 'free_for_all'),
    allowNull: false,
    defaultValue: 'attack_defend'
  },
  maxTeams: {
    type: DataTypes.INTEGER,
    allowNull: false,
    defaultValue: 2,
    validate: {
      min: 2,
      max: 8,
      isInt: true
    }
  },
  currentTeams: {
    type: DataTypes.INTEGER,
    allowNull: false,
    defaultValue: 0,
    validate: {
      min: 0,
      isInt: true
    }
  },
  duration: {
    type: DataTypes.INTEGER,
    allowNull: false,
    defaultValue: 3600, // 1 hour in seconds
    validate: {
      min: 300, // 5 minutes
      max: 28800, // 8 hours
      isInt: true
    },
    comment: 'Match duration in seconds'
  },
  startTime: {
    type: DataTypes.DATE,
    allowNull: true
  },
  endTime: {
    type: DataTypes.DATE,
    allowNull: true
  },
  actualEndTime: {
    type: DataTypes.DATE,
    allowNull: true,
    comment: 'When the match actually ended (may differ from planned endTime)'
  },
  scoringRules: {
    type: DataTypes.JSON,
    allowNull: false,
    defaultValue: JSON.stringify({
      flagCapture: 100,
      serviceHijack: 50,
      vulnerabilityExploit: 25,
      defensePoints: 10,
      timeBonus: 5,
      penalties: {
        downtime: -20,
        cheating: -100
      }
    }),
    get() {
      const rules = this.getDataValue('scoringRules');
      return typeof rules === 'string' ? JSON.parse(rules) : rules;
    },
    set(val) {
      this.setDataValue('scoringRules', typeof val === 'object' ? JSON.stringify(val) : val);
    },
    comment: 'JSON object defining point values for different actions'
  },
  networkConfig: {
    type: DataTypes.JSON,
    allowNull: true,
    get() {
      const config = this.getDataValue('networkConfig');
      return config ? (typeof config === 'string' ? JSON.parse(config) : config) : null;
    },
    set(val) {
      this.setDataValue('networkConfig', val ? JSON.stringify(val) : null);
    },
    comment: 'Network configuration for this match (VMs, segments, etc.)'
  },
  flags: {
    type: DataTypes.JSON,
    allowNull: true,
    get() {
      const flags = this.getDataValue('flags');
      return flags ? (typeof flags === 'string' ? JSON.parse(flags) : flags) : [];
    },
    set(val) {
      this.setDataValue('flags', val ? JSON.stringify(val) : null);
    },
    comment: 'Array of flags available in this match'
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
  packetCaptureEnabled: {
    type: DataTypes.BOOLEAN,
    allowNull: false,
    defaultValue: true,
    comment: 'Whether to capture packets during this match'
  },
  logAnalysisEnabled: {
    type: DataTypes.BOOLEAN,
    allowNull: false,
    defaultValue: true,
    comment: 'Whether to analyze logs for auto-scoring'
  },
  elkIntegration: {
    type: DataTypes.BOOLEAN,
    allowNull: false,
    defaultValue: false,
    comment: 'Whether ELK stack integration is available'
  },
  autoScoring: {
    type: DataTypes.BOOLEAN,
    allowNull: false,
    defaultValue: true,
    comment: 'Whether to enable automatic scoring based on network activity'
  },
  broadcastUpdates: {
    type: DataTypes.BOOLEAN,
    allowNull: false,
    defaultValue: true,
    comment: 'Whether to broadcast real-time updates via WebSocket'
  }
}, {
  timestamps: true,
  indexes: [
    {
      fields: ['status']
    },
    {
      fields: ['matchType']
    },
    {
      fields: ['startTime']
    },
    {
      fields: ['endTime']
    },
    {
      fields: ['createdBy']
    },
    {
      fields: ['status', 'startTime'],
      name: 'idx_match_active'
    }
  ],
  hooks: {
    beforeCreate: (match, options) => {
      // Set end time based on duration if start time is set
      if (match.startTime && match.duration) {
        match.endTime = new Date(match.startTime.getTime() + (match.duration * 1000));
      }
    },
    beforeUpdate: (match, options) => {
      // Update end time if start time or duration changes
      if (match.startTime && match.duration) {
        match.endTime = new Date(match.startTime.getTime() + (match.duration * 1000));
      }
      
      // Set actual end time when match finishes
      if (match.status === 'finished' && !match.actualEndTime) {
        match.actualEndTime = new Date();
      }
    }
  },
  scopes: {
    active: {
      where: {
        status: ['waiting', 'active', 'paused']
      }
    },
    finished: {
      where: {
        status: ['finished', 'cancelled']
      }
    },
    upcoming: {
      where: {
        status: 'waiting',
        startTime: {
          [sequelize.Sequelize.Op.gt]: new Date()
        }
      }
    }
  }
});

module.exports = Match;

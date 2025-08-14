const { DataTypes } = require('sequelize');
const { sequelize } = require('../config/db');

const ScoringEvent = sequelize.define('ScoringEvent', {
  id: {
    type: DataTypes.INTEGER,
    primaryKey: true,
    autoIncrement: true
  },
  matchId: {
    type: DataTypes.INTEGER,
    allowNull: false,
    references: {
      model: 'Matches',
      key: 'id'
    }
  },
  teamId: {
    type: DataTypes.INTEGER,
    allowNull: false,
    references: {
      model: 'Teams',
      key: 'id'
    }
  },
  userId: {
    type: DataTypes.INTEGER,
    allowNull: true, // Can be null for auto-scored events
    references: {
      model: 'Users',
      key: 'id'
    }
  },
  eventType: {
    type: DataTypes.ENUM(
      'flag_capture',
      'service_hijack', 
      'vulnerability_exploit',
      'defense_success',
      'attack_success',
      'service_downtime',
      'manual_adjustment',
      'penalty',
      'bonus',
      'network_compromise',
      'privilege_escalation',
      'data_exfiltration',
      'lateral_movement'
    ),
    allowNull: false
  },
  eventSubtype: {
    type: DataTypes.STRING,
    allowNull: true,
    comment: 'Specific subtype of the event (e.g., SQL injection, SSH brute force)'
  },
  points: {
    type: DataTypes.INTEGER,
    allowNull: false,
    validate: {
      isInt: true,
      min: -1000,
      max: 1000
    }
  },
  multiplier: {
    type: DataTypes.FLOAT,
    allowNull: false,
    defaultValue: 1.0,
    validate: {
      min: 0.0,
      max: 10.0
    },
    comment: 'Point multiplier based on difficulty, timing, etc.'
  },
  finalPoints: {
    type: DataTypes.INTEGER,
    allowNull: false,
    comment: 'Final points after applying multiplier (points * multiplier)'
  },
  description: {
    type: DataTypes.TEXT,
    allowNull: true
  },
  evidence: {
    type: DataTypes.JSON,
    allowNull: true,
    get() {
      const evidence = this.getDataValue('evidence');
      return evidence ? (typeof evidence === 'string' ? JSON.parse(evidence) : evidence) : null;
    },
    set(val) {
      this.setDataValue('evidence', val ? JSON.stringify(val) : null);
    },
    comment: 'JSON evidence supporting this scoring event (logs, network data, etc.)'
  },
  sourceType: {
    type: DataTypes.ENUM('manual', 'auto_network', 'auto_log', 'auto_elk', 'flag_submission', 'admin'),
    allowNull: false,
    defaultValue: 'manual'
  },
  sourceData: {
    type: DataTypes.JSON,
    allowNull: true,
    get() {
      const data = this.getDataValue('sourceData');
      return data ? (typeof data === 'string' ? JSON.parse(data) : data) : null;
    },
    set(val) {
      this.setDataValue('sourceData', val ? JSON.stringify(val) : null);
    },
    comment: 'Source data that triggered this event (packet capture, log entry, etc.)'
  },
  targetInfo: {
    type: DataTypes.JSON,
    allowNull: true,
    get() {
      const info = this.getDataValue('targetInfo');
      return info ? (typeof info === 'string' ? JSON.parse(info) : info) : null;
    },
    set(val) {
      this.setDataValue('targetInfo', val ? JSON.stringify(val) : null);
    },
    comment: 'Information about the target (IP, service, vulnerability)'
  },
  isVerified: {
    type: DataTypes.BOOLEAN,
    allowNull: false,
    defaultValue: false,
    comment: 'Whether this scoring event has been verified by an admin'
  },
  verifiedBy: {
    type: DataTypes.INTEGER,
    allowNull: true,
    references: {
      model: 'Users',
      key: 'id'
    }
  },
  verifiedAt: {
    type: DataTypes.DATE,
    allowNull: true
  },
  isActive: {
    type: DataTypes.BOOLEAN,
    allowNull: false,
    defaultValue: true,
    comment: 'Whether this scoring event is currently active/valid'
  },
  // Air-gapped specific fields
  networkFlow: {
    type: DataTypes.JSON,
    allowNull: true,
    get() {
      const flow = this.getDataValue('networkFlow');
      return flow ? (typeof flow === 'string' ? JSON.parse(flow) : flow) : null;
    },
    set(val) {
      this.setDataValue('networkFlow', val ? JSON.stringify(val) : null);
    },
    comment: 'Network flow information (src/dst IPs, ports, protocols)'
  },
  packetCaptureFile: {
    type: DataTypes.STRING,
    allowNull: true,
    comment: 'Path to packet capture file containing evidence'
  },
  logEntries: {
    type: DataTypes.JSON,
    allowNull: true,
    get() {
      const entries = this.getDataValue('logEntries');
      return entries ? (typeof entries === 'string' ? JSON.parse(entries) : entries) : [];
    },
    set(val) {
      this.setDataValue('logEntries', val ? JSON.stringify(val) : null);
    },
    comment: 'Related log entries that support this scoring event'
  },
  confidence: {
    type: DataTypes.FLOAT,
    allowNull: false,
    defaultValue: 1.0,
    validate: {
      min: 0.0,
      max: 1.0
    },
    comment: 'Confidence level of auto-scored events (0.0 to 1.0)'
  }
}, {
  timestamps: true,
  indexes: [
    {
      fields: ['matchId']
    },
    {
      fields: ['teamId']
    },
    {
      fields: ['userId']
    },
    {
      fields: ['eventType']
    },
    {
      fields: ['sourceType']
    },
    {
      fields: ['isActive']
    },
    {
      fields: ['isVerified']
    },
    {
      fields: ['createdAt']
    },
    {
      fields: ['matchId', 'teamId'],
      name: 'idx_scoring_match_team'
    },
    {
      fields: ['matchId', 'createdAt'],
      name: 'idx_scoring_timeline'
    },
    {
      fields: ['eventType', 'sourceType'],
      name: 'idx_scoring_classification'
    }
  ],
  hooks: {
    beforeCreate: (event, options) => {
      // Calculate final points
      event.finalPoints = Math.round(event.points * event.multiplier);
    },
    beforeUpdate: (event, options) => {
      // Recalculate final points if points or multiplier changed
      if (event.changed('points') || event.changed('multiplier')) {
        event.finalPoints = Math.round(event.points * event.multiplier);
      }
    }
  },
  scopes: {
    verified: {
      where: {
        isVerified: true
      }
    },
    active: {
      where: {
        isActive: true
      }
    },
    autoScored: {
      where: {
        sourceType: ['auto_network', 'auto_log', 'auto_elk']
      }
    },
    manual: {
      where: {
        sourceType: ['manual', 'admin', 'flag_submission']
      }
    },
    highValue: {
      where: {
        finalPoints: {
          [sequelize.Sequelize.Op.gte]: 50
        }
      }
    }
  }
});

module.exports = ScoringEvent;

const { DataTypes } = require('sequelize');
const { sequelize } = require('../config/db');

const Flag = sequelize.define('Flag', {
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
  name: {
    type: DataTypes.STRING,
    allowNull: false,
    validate: {
      notEmpty: true,
      len: [1, 100]
    }
  },
  description: {
    type: DataTypes.TEXT,
    allowNull: true
  },
  flagValue: {
    type: DataTypes.STRING,
    allowNull: false,
    validate: {
      notEmpty: true
    },
    comment: 'The actual flag value that teams need to submit'
  },
  points: {
    type: DataTypes.INTEGER,
    allowNull: false,
    validate: {
      min: 1,
      max: 1000
    }
  },
  category: {
    type: DataTypes.ENUM(
      'web',
      'network', 
      'crypto',
      'forensics',
      'reversing',
      'pwn',
      'misc',
      'osint',
      'steganography'
    ),
    allowNull: false,
    defaultValue: 'misc'
  },
  difficulty: {
    type: DataTypes.ENUM('beginner', 'intermediate', 'advanced'),
    allowNull: false,
    defaultValue: 'beginner'
  },
  isActive: {
    type: DataTypes.BOOLEAN,
    allowNull: false,
    defaultValue: true
  },
  capturedBy: {
    type: DataTypes.INTEGER,
    allowNull: true,
    references: {
      model: 'Teams',
      key: 'id'
    },
    comment: 'Team ID that captured this flag (null if not captured)'
  },
  capturedAt: {
    type: DataTypes.DATE,
    allowNull: true,
    comment: 'Timestamp when flag was captured'
  },
  capturedByUser: {
    type: DataTypes.INTEGER,
    allowNull: true,
    references: {
      model: 'Users',
      key: 'id'
    },
    comment: 'User ID who submitted the flag'
  },
  hints: {
    type: DataTypes.JSON,
    allowNull: true,
    get() {
      const hints = this.getDataValue('hints');
      return hints ? (typeof hints === 'string' ? JSON.parse(hints) : hints) : [];
    },
    set(val) {
      this.setDataValue('hints', val ? JSON.stringify(val) : null);
    },
    comment: 'Array of hints for this flag'
  },
  createdBy: {
    type: DataTypes.INTEGER,
    allowNull: false,
    references: {
      model: 'Users',
      key: 'id'
    }
  }
}, {
  timestamps: true,
  indexes: [
    {
      fields: ['matchId']
    },
    {
      fields: ['category']
    },
    {
      fields: ['difficulty']
    },
    {
      fields: ['isActive']
    },
    {
      fields: ['capturedBy']
    }
  ]
});

module.exports = Flag;

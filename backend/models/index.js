const { DataTypes } = require('sequelize');
const { sequelize } = require('../config/db');
const User = require('./User');
const Lab = require('./Lab');
const VM = require('./VM');
const FlagSubmission = require('./FlagSubmission');
const WebLab = require('./WebLab');
const WebLabCompletion = require('./WebLabCompletion');
// Phase 2 models
const Team = require('./Team');
const Match = require('./Match');
const ScoringEvent = require('./ScoringEvent');

// Define associations with optimized indexing
User.hasMany(Lab, { 
  foreignKey: 'createdBy', 
  as: 'createdLabs',
  constraints: true,
  onDelete: 'CASCADE'
});

Lab.belongsTo(User, { 
  foreignKey: 'createdBy', 
  as: 'creator',
  constraints: true
});

User.hasMany(VM, { 
  foreignKey: 'userId', 
  as: 'vms',
  constraints: true,
  onDelete: 'CASCADE'
});

VM.belongsTo(User, { 
  foreignKey: 'userId', 
  as: 'user',
  constraints: true
});

Lab.hasMany(VM, { 
  foreignKey: 'labId', 
  as: 'vms',
  constraints: true,
  onDelete: 'CASCADE'
});

VM.belongsTo(Lab, { 
  foreignKey: 'labId', 
  as: 'lab',
  constraints: true
});

// WebLab associations
Lab.hasOne(WebLab, {
  foreignKey: 'labId',
  as: 'webLabData',  // Changed from 'webLab' to 'webLabData' to avoid conflict
  constraints: true,
  onDelete: 'CASCADE'
});

WebLab.belongsTo(Lab, {
  foreignKey: 'labId',
  as: 'labDetails',  // Changed from 'lab' to 'labDetails' to be more specific
  constraints: true
});

// Many-to-many relationship between Users and Labs (for assigned labs)
// Using a custom junction model with optimized indexes
const UserLab = sequelize.define('UserLab', {
  id: {
    type: DataTypes.INTEGER,
    primaryKey: true,
    autoIncrement: true
  },
  userId: {
    type: DataTypes.INTEGER,
    allowNull: false
  },
  labId: {
    type: DataTypes.INTEGER,
    allowNull: false
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
    }
  ]
});

// Define the many-to-many relationship using the custom junction model
User.belongsToMany(Lab, { 
  through: UserLab,
  foreignKey: 'userId',
  as: 'assignedLabs'
});

Lab.belongsToMany(User, { 
  through: UserLab,
  foreignKey: 'labId',
  as: 'assignedUsers'
});

// FlagSubmission associations
User.hasMany(FlagSubmission, { 
  foreignKey: 'userId', 
  as: 'flagSubmissions',
  constraints: true,
  onDelete: 'CASCADE'
});

FlagSubmission.belongsTo(User, { 
  foreignKey: 'userId', 
  as: 'user',
  constraints: true
});

Lab.hasMany(FlagSubmission, { 
  foreignKey: 'labId', 
  as: 'flagSubmissions',
  constraints: true,
  onDelete: 'CASCADE'
});

FlagSubmission.belongsTo(Lab, { 
  foreignKey: 'labId', 
  as: 'lab',
  constraints: true
});

// WebLabCompletion associations
User.hasMany(WebLabCompletion, {
  foreignKey: 'userId',
  as: 'webLabCompletions',
  constraints: true,
  onDelete: 'CASCADE'
});

WebLabCompletion.belongsTo(User, {
  foreignKey: 'userId',
  as: 'user',
  constraints: true
});

Lab.hasMany(WebLabCompletion, {
  foreignKey: 'labId',
  as: 'webLabCompletions',
  constraints: true,
  onDelete: 'CASCADE'
});

WebLabCompletion.belongsTo(Lab, {
  foreignKey: 'labId',
  as: 'lab',
  constraints: true
});

// Phase 2 Team associations
User.belongsToMany(Team, {
  through: 'UserTeam',
  foreignKey: 'userId',
  as: 'teams'
});

Team.belongsToMany(User, {
  through: 'UserTeam',
  foreignKey: 'teamId',
  as: 'members'
});

User.hasMany(Team, {
  foreignKey: 'createdBy',
  as: 'createdTeams'
});

Team.belongsTo(User, {
  foreignKey: 'createdBy',
  as: 'creator'
});

// Phase 2 Match associations
User.hasMany(Match, {
  foreignKey: 'createdBy',
  as: 'createdMatches'
});

Match.belongsTo(User, {
  foreignKey: 'createdBy',
  as: 'creator'
});

Team.belongsToMany(Match, {
  through: 'TeamMatch',
  foreignKey: 'teamId',
  as: 'matches'
});

Match.belongsToMany(Team, {
  through: 'TeamMatch',
  foreignKey: 'matchId',
  as: 'teams'
});

// Phase 2 ScoringEvent associations
Match.hasMany(ScoringEvent, {
  foreignKey: 'matchId',
  as: 'scoringEvents',
  onDelete: 'CASCADE'
});

ScoringEvent.belongsTo(Match, {
  foreignKey: 'matchId',
  as: 'match'
});

Team.hasMany(ScoringEvent, {
  foreignKey: 'teamId',
  as: 'scoringEvents',
  onDelete: 'CASCADE'
});

ScoringEvent.belongsTo(Team, {
  foreignKey: 'teamId',
  as: 'team'
});

User.hasMany(ScoringEvent, {
  foreignKey: 'userId',
  as: 'scoringEvents',
  onDelete: 'SET NULL'
});

ScoringEvent.belongsTo(User, {
  foreignKey: 'userId',
  as: 'user'
});

// Verification associations
User.hasMany(ScoringEvent, {
  foreignKey: 'verifiedBy',
  as: 'verifiedScoringEvents',
  onDelete: 'SET NULL'
});

ScoringEvent.belongsTo(User, {
  foreignKey: 'verifiedBy',
  as: 'verifier'
});

// Enhanced FlagSubmission for Phase 2
Team.hasMany(FlagSubmission, {
  foreignKey: 'teamId',
  as: 'flagSubmissions',
  onDelete: 'CASCADE'
});

FlagSubmission.belongsTo(Team, {
  foreignKey: 'teamId',
  as: 'team'
});

Match.hasMany(FlagSubmission, {
  foreignKey: 'matchId',
  as: 'flagSubmissions',
  onDelete: 'CASCADE'
});

FlagSubmission.belongsTo(Match, {
  foreignKey: 'matchId',
  as: 'match'
});

// Add the UserLab model and Phase 2 models to exports
module.exports = {
  User,
  Lab,
  VM,
  UserLab,
  FlagSubmission,
  WebLab,
  WebLabCompletion,
  // Phase 2 models
  Team,
  Match,
  ScoringEvent
};

'use strict';

module.exports = {
  up: async (queryInterface, Sequelize) => {
    // Create Matches table
    await queryInterface.createTable('Matches', {
      id: {
        type: Sequelize.INTEGER,
        primaryKey: true,
        autoIncrement: true
      },
      name: {
        type: Sequelize.STRING,
        allowNull: false
      },
      description: {
        type: Sequelize.TEXT,
        allowNull: true
      },
      status: {
        type: Sequelize.ENUM('setup', 'waiting', 'active', 'paused', 'finished', 'cancelled'),
        allowNull: false,
        defaultValue: 'setup'
      },
      matchType: {
        type: Sequelize.ENUM('attack_defend', 'capture_flag', 'red_vs_blue', 'free_for_all'),
        allowNull: false,
        defaultValue: 'attack_defend'
      },
      maxTeams: {
        type: Sequelize.INTEGER,
        allowNull: false,
        defaultValue: 2
      },
      currentTeams: {
        type: Sequelize.INTEGER,
        allowNull: false,
        defaultValue: 0
      },
      duration: {
        type: Sequelize.INTEGER,
        allowNull: false,
        defaultValue: 3600
      },
      startTime: {
        type: Sequelize.DATE,
        allowNull: true
      },
      endTime: {
        type: Sequelize.DATE,
        allowNull: true
      },
      actualEndTime: {
        type: Sequelize.DATE,
        allowNull: true
      },
      scoringRules: {
        type: Sequelize.TEXT,
        allowNull: true
      },
      networkConfig: {
        type: Sequelize.TEXT,
        allowNull: true
      },
      vmConfig: {
        type: Sequelize.TEXT,
        allowNull: true
      },
      flags: {
        type: Sequelize.TEXT,
        allowNull: true
      },
      createdBy: {
        type: Sequelize.INTEGER,
        allowNull: false,
        references: {
          model: 'Users',
          key: 'id'
        }
      },
      createdAt: {
        allowNull: false,
        type: Sequelize.DATE
      },
      updatedAt: {
        allowNull: false,
        type: Sequelize.DATE
      }
    });

    // Create Teams table
    await queryInterface.createTable('Teams', {
      id: {
        type: Sequelize.INTEGER,
        primaryKey: true,
        autoIncrement: true
      },
      name: {
        type: Sequelize.STRING,
        allowNull: false,
        unique: true
      },
      description: {
        type: Sequelize.TEXT,
        allowNull: true
      },
      score: {
        type: Sequelize.INTEGER,
        allowNull: false,
        defaultValue: 0
      },
      rank: {
        type: Sequelize.INTEGER,
        allowNull: true
      },
      isActive: {
        type: Sequelize.BOOLEAN,
        allowNull: false,
        defaultValue: true
      },
      matchId: {
        type: Sequelize.INTEGER,
        allowNull: false,
        references: {
          model: 'Matches',
          key: 'id'
        }
      },
      createdAt: {
        allowNull: false,
        type: Sequelize.DATE
      },
      updatedAt: {
        allowNull: false,
        type: Sequelize.DATE
      }
    });

    // Create TeamMembers join table
    await queryInterface.createTable('TeamMembers', {
      id: {
        type: Sequelize.INTEGER,
        primaryKey: true,
        autoIncrement: true
      },
      teamId: {
        type: Sequelize.INTEGER,
        allowNull: false,
        references: {
          model: 'Teams',
          key: 'id'
        }
      },
      userId: {
        type: Sequelize.INTEGER,
        allowNull: false,
        references: {
          model: 'Users',
          key: 'id'
        }
      },
      isLeader: {
        type: Sequelize.BOOLEAN,
        allowNull: false,
        defaultValue: false
      },
      joinedAt: {
        allowNull: false,
        type: Sequelize.DATE,
        defaultValue: Sequelize.literal('CURRENT_TIMESTAMP')
      },
      createdAt: {
        allowNull: false,
        type: Sequelize.DATE
      },
      updatedAt: {
        allowNull: false,
        type: Sequelize.DATE
      }
    });

    // Create ScoringEvents table
    await queryInterface.createTable('ScoringEvents', {
      id: {
        type: Sequelize.INTEGER,
        primaryKey: true,
        autoIncrement: true
      },
      eventType: {
        type: Sequelize.STRING,
        allowNull: false
      },
      points: {
        type: Sequelize.INTEGER,
        allowNull: false
      },
      description: {
        type: Sequelize.TEXT,
        allowNull: true
      },
      metadata: {
        type: Sequelize.TEXT,
        allowNull: true
      },
      matchId: {
        type: Sequelize.INTEGER,
        allowNull: false,
        references: {
          model: 'Matches',
          key: 'id'
        }
      },
      teamId: {
        type: Sequelize.INTEGER,
        allowNull: true,
        references: {
          model: 'Teams',
          key: 'id'
        }
      },
      userId: {
        type: Sequelize.INTEGER,
        allowNull: true,
        references: {
          model: 'Users',
          key: 'id'
        }
      },
      createdAt: {
        allowNull: false,
        type: Sequelize.DATE
      },
      updatedAt: {
        allowNull: false,
        type: Sequelize.DATE
      }
    });

    // Add indexes for better query performance
    await queryInterface.addIndex('Teams', ['matchId']);
    await queryInterface.addIndex('TeamMembers', ['teamId']);
    await queryInterface.addIndex('TeamMembers', ['userId']);
    await queryInterface.addIndex('ScoringEvents', ['matchId']);
    await queryInterface.addIndex('ScoringEvents', ['teamId']);
    await queryInterface.addIndex('ScoringEvents', ['userId']);
  },

  down: async (queryInterface, Sequelize) => {
    // Drop tables in reverse order to respect foreign key constraints
    await queryInterface.dropTable('ScoringEvents');
    await queryInterface.dropTable('TeamMembers');
    await queryInterface.dropTable('Teams');
    await queryInterface.dropTable('Matches');
  }
};

const { DataTypes } = require('sequelize');

module.exports = {
  up: async (queryInterface, Sequelize) => {
    await queryInterface.createTable('Flags', {
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
        },
        onUpdate: 'CASCADE',
        onDelete: 'CASCADE'
      },
      name: {
        type: DataTypes.STRING,
        allowNull: false
      },
      description: {
        type: DataTypes.TEXT,
        allowNull: true
      },
      flagValue: {
        type: DataTypes.STRING,
        allowNull: false
      },
      points: {
        type: DataTypes.INTEGER,
        allowNull: false
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
        onUpdate: 'CASCADE',
        onDelete: 'SET NULL'
      },
      capturedAt: {
        type: DataTypes.DATE,
        allowNull: true
      },
      capturedByUser: {
        type: DataTypes.INTEGER,
        allowNull: true,
        references: {
          model: 'Users',
          key: 'id'
        },
        onUpdate: 'CASCADE',
        onDelete: 'SET NULL'
      },
      hints: {
        type: DataTypes.JSON,
        allowNull: true
      },
      createdBy: {
        type: DataTypes.INTEGER,
        allowNull: false,
        references: {
          model: 'Users',
          key: 'id'
        },
        onUpdate: 'CASCADE',
        onDelete: 'RESTRICT'
      },
      createdAt: {
        type: DataTypes.DATE,
        allowNull: false,
        defaultValue: Sequelize.literal('CURRENT_TIMESTAMP')
      },
      updatedAt: {
        type: DataTypes.DATE,
        allowNull: false,
        defaultValue: Sequelize.literal('CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP')
      }
    });

    // Add indexes
    await queryInterface.addIndex('Flags', ['matchId']);
    await queryInterface.addIndex('Flags', ['category']);
    await queryInterface.addIndex('Flags', ['difficulty']);
    await queryInterface.addIndex('Flags', ['isActive']);
    await queryInterface.addIndex('Flags', ['capturedBy']);
  },

  down: async (queryInterface, Sequelize) => {
    await queryInterface.dropTable('Flags');
  }
};

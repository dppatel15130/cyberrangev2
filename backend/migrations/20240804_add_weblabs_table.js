'use strict';

module.exports = {
  up: async (queryInterface, Sequelize) => {
    // Create WebLabs table
    await queryInterface.createTable('WebLabs', {
      id: {
        type: Sequelize.INTEGER,
        primaryKey: true,
        autoIncrement: true
      },
      labId: {
        type: Sequelize.INTEGER,
        allowNull: false,
        references: {
          model: 'Labs',
          key: 'id'
        },
        onUpdate: 'CASCADE',
        onDelete: 'CASCADE'
      },
      htmlContent: {
        type: Sequelize.TEXT,
        allowNull: false
      },
      validationType: {
        type: Sequelize.ENUM('header_check', 'input_flag'),
        allowNull: false,
        defaultValue: 'header_check'
      },
      validationValue: {
        type: Sequelize.STRING,
        allowNull: false,
        comment: 'e.g., "Lab-Status: Completed" for header_check or the expected flag for input_flag'
      },
      allowedOrigins: {
        type: Sequelize.TEXT,
        allowNull: true,
        comment: 'Comma-separated list of allowed origins for CORS',
        get() {
          const origins = this.getDataValue('allowedOrigins');
          return origins ? origins.split(',') : [];
        },
        set(val) {
          this.setDataValue('allowedOrigins', Array.isArray(val) ? val.join(',') : val);
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

    // Add labType 'web' to the Lab model
    await queryInterface.sequelize.query(
      'ALTER TABLE `Labs` MODIFY COLUMN `labType` VARCHAR(255) NOT NULL DEFAULT "vm"'
    );
    
    // Update existing NULL values to 'vm' as default
    await queryInterface.sequelize.query(
      'UPDATE `Labs` SET `labType` = "vm" WHERE `labType` IS NULL OR `labType` = ""'
    );
  },

  down: async (queryInterface, Sequelize) => {
    await queryInterface.dropTable('WebLabs');
    
    // Revert labType changes - set 'web' back to 'special'
    await queryInterface.sequelize.query(
      'UPDATE `Labs` SET `labType` = "special" WHERE `labType` = "web"'
    );
  }
};

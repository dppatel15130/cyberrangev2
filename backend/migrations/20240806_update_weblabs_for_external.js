'use strict';

module.exports = {
  up: async (queryInterface, Sequelize) => {
    // Check if hostedUrl column already exists
    const tableInfo = await queryInterface.describeTable('WebLabs');
    
    // Add hostedUrl column to WebLabs table if it doesn't exist
    if (!tableInfo.hostedUrl) {
      await queryInterface.addColumn('WebLabs', 'hostedUrl', {
        type: Sequelize.STRING,
        allowNull: true,
        comment: 'External URL where the lab is hosted'
      });
      console.log('Added hostedUrl column to WebLabs table');
    } else {
      console.log('hostedUrl column already exists in WebLabs table');
    }

    // Modify validationType to include 'callback' option
    await queryInterface.sequelize.query(
      'ALTER TABLE `WebLabs` MODIFY COLUMN `validationType` ENUM("header_check", "input_flag", "callback") NOT NULL DEFAULT "header_check"'
    );
  },

  down: async (queryInterface, Sequelize) => {
    // Check if hostedUrl column exists before removing it
    const tableInfo = await queryInterface.describeTable('WebLabs');
    
    // Remove hostedUrl column if it exists
    if (tableInfo.hostedUrl) {
      await queryInterface.removeColumn('WebLabs', 'hostedUrl');
      console.log('Removed hostedUrl column from WebLabs table');
    } else {
      console.log('hostedUrl column does not exist in WebLabs table');
    }

    // Revert validationType to original options
    await queryInterface.sequelize.query(
      'ALTER TABLE `WebLabs` MODIFY COLUMN `validationType` ENUM("header_check", "input_flag") NOT NULL DEFAULT "header_check"'
    );
  }
};
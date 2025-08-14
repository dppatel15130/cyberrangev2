'use strict';

module.exports = {
  up: async (queryInterface, Sequelize) => {
    // Check if the columns exist before trying to remove them
    const tableInfo = await queryInterface.describeTable('Labs');
    
    if (tableInfo.objectives) {
      await queryInterface.removeColumn('Labs', 'objectives');
    }
    
    if (tableInfo.requirements) {
      await queryInterface.removeColumn('Labs', 'requirements');
    }
  },

  down: async (queryInterface, Sequelize) => {
    // Add the columns back if we need to rollback
    await queryInterface.addColumn('Labs', 'objectives', {
      type: Sequelize.JSON,
      allowNull: true,
      defaultValue: []
    });
    
    await queryInterface.addColumn('Labs', 'requirements', {
      type: Sequelize.JSON,
      allowNull: true,
      defaultValue: []
    });
  }
};

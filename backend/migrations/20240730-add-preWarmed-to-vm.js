'use strict';

module.exports = {
  up: async (queryInterface, Sequelize) => {
    try {
      // First check if the column already exists
      const [results] = await queryInterface.sequelize.query(
        "SHOW COLUMNS FROM `VMs` LIKE 'preWarmed'"
      );
      
      // If the column doesn't exist, add it
      if (results.length === 0) {
        await queryInterface.addColumn('VMs', 'preWarmed', {
          type: Sequelize.BOOLEAN,
          allowNull: false,
          defaultValue: false
        });
        console.log('Added preWarmed column to VMs table');
      } else {
        console.log('preWarmed column already exists in VMs table');
      }
    } catch (error) {
      console.error('Error in migration:', error);
      throw error;
    }
  },

  down: async (queryInterface, Sequelize) => {
    try {
      await queryInterface.removeColumn('VMs', 'preWarmed');
      console.log('Removed preWarmed column from VMs table');
    } catch (error) {
      console.error('Error rolling back migration:', error);
      throw error;
    }
  }
};

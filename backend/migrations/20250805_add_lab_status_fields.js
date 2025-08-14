'use strict';

module.exports = {
  async up(queryInterface, Sequelize) {
    // Add status field
    await queryInterface.addColumn('Labs', 'status', {
      type: Sequelize.ENUM('draft', 'active', 'inactive', 'archived'),
      defaultValue: 'draft',
      allowNull: false,
      after: 'points'
    });

    // Add lastModified field
    await queryInterface.addColumn('Labs', 'lastModified', {
      type: Sequelize.DATE,
      defaultValue: Sequelize.NOW,
      allowNull: false,
      after: 'status'
    });

    // Add tags field
    await queryInterface.addColumn('Labs', 'tags', {
      type: Sequelize.JSON,
      allowNull: true,
      defaultValue: '[]',
      after: 'lastModified'
    });

    // Update existing labs to have 'active' status if they are currently active
    await queryInterface.sequelize.query(
      "UPDATE Labs SET status = 'active' WHERE isActive = 1"
    );

    // Update existing labs to have 'inactive' status if they are currently inactive
    await queryInterface.sequelize.query(
      "UPDATE Labs SET status = 'inactive' WHERE isActive = 0"
    );

    console.log('Successfully added status, lastModified, and tags fields to Labs table');
  },

  async down(queryInterface, Sequelize) {
    // Remove the added columns
    await queryInterface.removeColumn('Labs', 'tags');
    await queryInterface.removeColumn('Labs', 'lastModified');
    await queryInterface.removeColumn('Labs', 'status');

    console.log('Successfully removed status, lastModified, and tags fields from Labs table');
  }
};

const { sequelize } = require('../config/db');

async function fixMySQLIndexes() {
  try {
    console.log('=== Fixing MySQL Index Limit Issue ===\n');

    // Check current indexes for all tables
    const [results] = await sequelize.query(`
      SELECT 
        TABLE_NAME, 
        INDEX_NAME, 
        NON_UNIQUE,
        COLUMN_NAME
      FROM INFORMATION_SCHEMA.STATISTICS 
      WHERE TABLE_SCHEMA = 'cyberrangev3' 
      ORDER BY TABLE_NAME, INDEX_NAME;
    `);

    console.log(`Total indexes found: ${results.length}\n`);

    // Group by table
    const indexesByTable = {};
    results.forEach(row => {
      if (!indexesByTable[row.TABLE_NAME]) {
        indexesByTable[row.TABLE_NAME] = {};
      }
      if (!indexesByTable[row.TABLE_NAME][row.INDEX_NAME]) {
        indexesByTable[row.TABLE_NAME][row.INDEX_NAME] = [];
      }
      indexesByTable[row.TABLE_NAME][row.INDEX_NAME].push(row.COLUMN_NAME);
    });

    // Display current indexes
    for (const table in indexesByTable) {
      console.log(`\n${table}:`);
      for (const index in indexesByTable[table]) {
        const columns = indexesByTable[table][index].join(', ');
        console.log(`  - ${index}: (${columns})`);
      }
    }

    console.log('\n=== Removing Unnecessary Indexes ===\n');

    // Remove duplicate and unnecessary indexes to stay under the 64-key limit
    const unnecessaryIndexes = [
      // Remove redundant indexes on VMs table
      'DROP INDEX IF EXISTS `VMs_ibfk_50` ON `VMs`',
      'DROP INDEX IF EXISTS `VMs_ibfk_51` ON `VMs`', 
      'DROP INDEX IF EXISTS `VMs_ibfk_52` ON `VMs`',
      'DROP INDEX IF EXISTS `VMs_ibfk_53` ON `VMs`',
      'DROP INDEX IF EXISTS `VMs_ibfk_54` ON `VMs`',
      'DROP INDEX IF EXISTS `VMs_ibfk_55` ON `VMs`',
      'DROP INDEX IF EXISTS `VMs_ibfk_56` ON `VMs`',
      'DROP INDEX IF EXISTS `VMs_ibfk_57` ON `VMs`',
      'DROP INDEX IF EXISTS `VMs_ibfk_58` ON `VMs`',
      'DROP INDEX IF EXISTS `VMs_ibfk_59` ON `VMs`',
      'DROP INDEX IF EXISTS `VMs_ibfk_60` ON `VMs`',
      
      // Remove redundant indexes on other tables that might have accumulated
      'DROP INDEX IF EXISTS `Teams_ibfk_20` ON `Teams`',
      'DROP INDEX IF EXISTS `Teams_ibfk_21` ON `Teams`',
      'DROP INDEX IF EXISTS `Teams_ibfk_22` ON `Teams`',
      'DROP INDEX IF EXISTS `Teams_ibfk_23` ON `Teams`',
      'DROP INDEX IF EXISTS `Teams_ibfk_24` ON `Teams`',
      'DROP INDEX IF EXISTS `Teams_ibfk_25` ON `Teams`',
      
      'DROP INDEX IF EXISTS `Matches_ibfk_20` ON `Matches`',
      'DROP INDEX IF EXISTS `Matches_ibfk_21` ON `Matches`',
      'DROP INDEX IF EXISTS `Matches_ibfk_22` ON `Matches`',
      
      'DROP INDEX IF EXISTS `Flags_ibfk_20` ON `Flags`',
      'DROP INDEX IF EXISTS `Flags_ibfk_21` ON `Flags`',
      'DROP INDEX IF EXISTS `Flags_ibfk_22` ON `Flags`',
      
      // Remove old foreign key indexes that might be duplicated
      'DROP INDEX IF EXISTS `userId` ON `VMs`',
      'DROP INDEX IF EXISTS `labId` ON `VMs`',
      'DROP INDEX IF EXISTS `createdBy` ON `Teams`',
      'DROP INDEX IF EXISTS `createdBy` ON `Matches`',
      'DROP INDEX IF EXISTS `createdBy` ON `Flags`'
    ];

    for (const dropQuery of unnecessaryIndexes) {
      try {
        await sequelize.query(dropQuery);
        console.log(`✅ Executed: ${dropQuery.split(' ON ')[0]}`);
      } catch (error) {
        if (!error.message.includes("check that it exists")) {
          console.log(`⚠️  Warning: ${dropQuery.split(' ON ')[0]} - ${error.message}`);
        }
      }
    }

    console.log('\n=== Recreating Essential Indexes Only ===\n');

    // Recreate only essential indexes
    const essentialIndexes = [
      // VMs table - only keep the most important ones
      'CREATE INDEX IF NOT EXISTS `idx_vms_user` ON `VMs` (`userId`)',
      'CREATE INDEX IF NOT EXISTS `idx_vms_lab` ON `VMs` (`labId`)',
      'CREATE INDEX IF NOT EXISTS `idx_vms_status` ON `VMs` (`status`)',
      
      // Teams table
      'CREATE INDEX IF NOT EXISTS `idx_teams_active` ON `Teams` (`isActive`)',
      'CREATE INDEX IF NOT EXISTS `idx_teams_creator` ON `Teams` (`createdBy`)',
      
      // Matches table
      'CREATE INDEX IF NOT EXISTS `idx_matches_status` ON `Matches` (`status`)',
      'CREATE INDEX IF NOT EXISTS `idx_matches_creator` ON `Matches` (`createdBy`)',
      
      // Flags table
      'CREATE INDEX IF NOT EXISTS `idx_flags_match` ON `Flags` (`matchId`)',
      'CREATE INDEX IF NOT EXISTS `idx_flags_active` ON `Flags` (`isActive`)',
      'CREATE INDEX IF NOT EXISTS `idx_flags_captured` ON `Flags` (`capturedBy`)'
    ];

    for (const createQuery of essentialIndexes) {
      try {
        await sequelize.query(createQuery);
        console.log(`✅ Created: ${createQuery.match(/idx_\w+/)[0]}`);
      } catch (error) {
        console.log(`⚠️  Warning: ${createQuery.match(/idx_\w+/)[0]} - ${error.message}`);
      }
    }

    console.log('\n=== Checking Final Index Count ===\n');

    // Check final count
    const [finalResults] = await sequelize.query(`
      SELECT COUNT(*) as total_indexes
      FROM INFORMATION_SCHEMA.STATISTICS 
      WHERE TABLE_SCHEMA = 'cyberrangev3';
    `);

    console.log(`Final total indexes: ${finalResults[0].total_indexes}`);
    
    if (finalResults[0].total_indexes < 64) {
      console.log('✅ Index count is now under the MySQL limit of 64!');
    } else {
      console.log('⚠️  Still above limit. Manual cleanup may be needed.');
    }

  } catch (error) {
    console.error('Error fixing indexes:', error);
  } finally {
    await sequelize.close();
    process.exit(0);
  }
}

fixMySQLIndexes();

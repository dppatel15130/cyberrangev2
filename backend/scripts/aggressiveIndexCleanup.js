const { sequelize } = require('../config/db');

async function aggressiveIndexCleanup() {
  try {
    console.log('=== Aggressive MySQL Index Cleanup ===\n');

    // Drop all duplicate indexes aggressively
    const dropDuplicateIndexes = [
      // Users table - remove all duplicate indexes except one for each field
      'DROP INDEX IF EXISTS `email_2` ON `Users`',
      'DROP INDEX IF EXISTS `email_3` ON `Users`',
      'DROP INDEX IF EXISTS `email_4` ON `Users`',
      'DROP INDEX IF EXISTS `email_5` ON `Users`',
      'DROP INDEX IF EXISTS `email_6` ON `Users`',
      'DROP INDEX IF EXISTS `email_7` ON `Users`',
      'DROP INDEX IF EXISTS `email_8` ON `Users`',
      'DROP INDEX IF EXISTS `email_9` ON `Users`',
      'DROP INDEX IF EXISTS `email_10` ON `Users`',
      'DROP INDEX IF EXISTS `email_11` ON `Users`',
      'DROP INDEX IF EXISTS `email_12` ON `Users`',
      'DROP INDEX IF EXISTS `email_13` ON `Users`',
      'DROP INDEX IF EXISTS `email_14` ON `Users`',
      'DROP INDEX IF EXISTS `email_15` ON `Users`',
      'DROP INDEX IF EXISTS `email_16` ON `Users`',
      'DROP INDEX IF EXISTS `email_17` ON `Users`',
      'DROP INDEX IF EXISTS `email_18` ON `Users`',
      'DROP INDEX IF EXISTS `email_19` ON `Users`',
      'DROP INDEX IF EXISTS `email_20` ON `Users`',
      'DROP INDEX IF EXISTS `email_21` ON `Users`',
      'DROP INDEX IF EXISTS `email_22` ON `Users`',
      'DROP INDEX IF EXISTS `email_23` ON `Users`',
      'DROP INDEX IF EXISTS `email_24` ON `Users`',
      'DROP INDEX IF EXISTS `email_25` ON `Users`',
      'DROP INDEX IF EXISTS `email_26` ON `Users`',
      'DROP INDEX IF EXISTS `email_27` ON `Users`',
      'DROP INDEX IF EXISTS `email_28` ON `Users`',
      'DROP INDEX IF EXISTS `email_29` ON `Users`',
      'DROP INDEX IF EXISTS `email_30` ON `Users`',
      'DROP INDEX IF EXISTS `email_31` ON `Users`',
      
      'DROP INDEX IF EXISTS `username_2` ON `Users`',
      'DROP INDEX IF EXISTS `username_3` ON `Users`',
      'DROP INDEX IF EXISTS `username_4` ON `Users`',
      'DROP INDEX IF EXISTS `username_5` ON `Users`',
      'DROP INDEX IF EXISTS `username_6` ON `Users`',
      'DROP INDEX IF EXISTS `username_7` ON `Users`',
      'DROP INDEX IF EXISTS `username_8` ON `Users`',
      'DROP INDEX IF EXISTS `username_9` ON `Users`',
      'DROP INDEX IF EXISTS `username_10` ON `Users`',
      'DROP INDEX IF EXISTS `username_11` ON `Users`',
      'DROP INDEX IF EXISTS `username_12` ON `Users`',
      'DROP INDEX IF EXISTS `username_13` ON `Users`',
      'DROP INDEX IF EXISTS `username_14` ON `Users`',
      'DROP INDEX IF EXISTS `username_15` ON `Users`',
      'DROP INDEX IF EXISTS `username_16` ON `Users`',
      'DROP INDEX IF EXISTS `username_17` ON `Users`',
      'DROP INDEX IF EXISTS `username_18` ON `Users`',
      'DROP INDEX IF EXISTS `username_19` ON `Users`',
      'DROP INDEX IF EXISTS `username_20` ON `Users`',
      'DROP INDEX IF EXISTS `username_21` ON `Users`',
      'DROP INDEX IF EXISTS `username_22` ON `Users`',
      'DROP INDEX IF EXISTS `username_23` ON `Users`',
      'DROP INDEX IF EXISTS `username_24` ON `Users`',
      'DROP INDEX IF EXISTS `username_25` ON `Users`',
      'DROP INDEX IF EXISTS `username_26` ON `Users`',
      'DROP INDEX IF EXISTS `username_27` ON `Users`',
      'DROP INDEX IF EXISTS `username_28` ON `Users`',
      'DROP INDEX IF EXISTS `username_29` ON `Users`',
      'DROP INDEX IF EXISTS `username_30` ON `Users`',
      'DROP INDEX IF EXISTS `username_31` ON `Users`',
      'DROP INDEX IF EXISTS `username_32` ON `Users`',
      
      // Teams table - remove all duplicate name indexes except one
      'DROP INDEX IF EXISTS `name_2` ON `Teams`',
      'DROP INDEX IF EXISTS `name_3` ON `Teams`',
      'DROP INDEX IF EXISTS `name_4` ON `Teams`',
      'DROP INDEX IF EXISTS `name_5` ON `Teams`',
      'DROP INDEX IF EXISTS `name_6` ON `Teams`',
      'DROP INDEX IF EXISTS `name_7` ON `Teams`',
      'DROP INDEX IF EXISTS `name_8` ON `Teams`',
      'DROP INDEX IF EXISTS `name_9` ON `Teams`',
      'DROP INDEX IF EXISTS `name_10` ON `Teams`',
      'DROP INDEX IF EXISTS `name_11` ON `Teams`',
      'DROP INDEX IF EXISTS `name_12` ON `Teams`',
      'DROP INDEX IF EXISTS `name_13` ON `Teams`',
      'DROP INDEX IF EXISTS `name_14` ON `Teams`',
      'DROP INDEX IF EXISTS `name_15` ON `Teams`',
      'DROP INDEX IF EXISTS `name_16` ON `Teams`',
      'DROP INDEX IF EXISTS `name_17` ON `Teams`',
      'DROP INDEX IF EXISTS `name_18` ON `Teams`',
      'DROP INDEX IF EXISTS `name_19` ON `Teams`',
      'DROP INDEX IF EXISTS `name_20` ON `Teams`',
      'DROP INDEX IF EXISTS `name_21` ON `Teams`',
      'DROP INDEX IF EXISTS `name_22` ON `Teams`',
      'DROP INDEX IF EXISTS `name_23` ON `Teams`',
      'DROP INDEX IF EXISTS `name_24` ON `Teams`',
      'DROP INDEX IF EXISTS `name_25` ON `Teams`',
      'DROP INDEX IF EXISTS `name_26` ON `Teams`',
      'DROP INDEX IF EXISTS `name_27` ON `Teams`',
      'DROP INDEX IF EXISTS `name_28` ON `Teams`',
      'DROP INDEX IF EXISTS `name_29` ON `Teams`',
      'DROP INDEX IF EXISTS `name_30` ON `Teams`'
    ];

    console.log('Removing duplicate indexes...\n');
    let removed = 0;
    for (const dropQuery of dropDuplicateIndexes) {
      try {
        await sequelize.query(dropQuery);
        const indexName = dropQuery.match(/`([^`]+)`/)[1];
        console.log(`✅ Removed: ${indexName}`);
        removed++;
      } catch (error) {
        if (!error.message.includes("check that it exists")) {
          console.log(`⚠️  ${dropQuery.match(/`([^`]+)`/)[1]}: ${error.message.substring(0, 50)}...`);
        }
      }
    }

    console.log(`\n${removed} duplicate indexes removed successfully!\n`);

    // Check final count
    const [finalResults] = await sequelize.query(`
      SELECT COUNT(*) as total_indexes
      FROM INFORMATION_SCHEMA.STATISTICS 
      WHERE TABLE_SCHEMA = 'cyberrangev3';
    `);

    console.log(`Final total indexes: ${finalResults[0].total_indexes}`);
    
    if (finalResults[0].total_indexes <= 64) {
      console.log('✅ SUCCESS! Index count is now under the MySQL limit of 64!');
    } else {
      console.log(`⚠️  Still at ${finalResults[0].total_indexes} indexes. Need to remove ${finalResults[0].total_indexes - 64} more.`);
    }

    console.log('\n=== Index Cleanup Complete ===');

  } catch (error) {
    console.error('Error during aggressive cleanup:', error);
  } finally {
    await sequelize.close();
    process.exit(0);
  }
}

aggressiveIndexCleanup();

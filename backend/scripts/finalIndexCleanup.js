const { sequelize } = require('../config/db');

async function finalIndexCleanup() {
  try {
    console.log('=== Final MySQL Index Cleanup ===\n');

    // Remove additional non-essential indexes
    const additionalDrops = [
      // Remove old/redundant indexes
      'DROP INDEX IF EXISTS `teams_name` ON `Teams`',
      'DROP INDEX IF EXISTS `teams_created_by` ON `Teams`',
      'DROP INDEX IF EXISTS `teams_is_active` ON `Teams`',
      'DROP INDEX IF EXISTS `teams_last_activity` ON `Teams`',
      
      'DROP INDEX IF EXISTS `matches_created_by` ON `Matches`',
      'DROP INDEX IF EXISTS `matches_end_time` ON `Matches`',
      'DROP INDEX IF EXISTS `matches_match_type` ON `Matches`',
      'DROP INDEX IF EXISTS `matches_start_time` ON `Matches`',
      'DROP INDEX IF EXISTS `matches_status` ON `Matches`',
      
      'DROP INDEX IF EXISTS `flags_captured_by` ON `Flags`',
      'DROP INDEX IF EXISTS `flags_category` ON `Flags`',
      'DROP INDEX IF EXISTS `flags_difficulty` ON `Flags`',
      'DROP INDEX IF EXISTS `flags_is_active` ON `Flags`',
      'DROP INDEX IF EXISTS `flags_match_id` ON `Flags`',
      
      'DROP INDEX IF EXISTS `scoring_events_created_at` ON `ScoringEvents`',
      'DROP INDEX IF EXISTS `scoring_events_event_type` ON `ScoringEvents`',
      'DROP INDEX IF EXISTS `scoring_events_is_active` ON `ScoringEvents`',
      'DROP INDEX IF EXISTS `scoring_events_is_verified` ON `ScoringEvents`',
      'DROP INDEX IF EXISTS `scoring_events_match_id` ON `ScoringEvents`',
      'DROP INDEX IF EXISTS `scoring_events_source_type` ON `ScoringEvents`',
      'DROP INDEX IF EXISTS `scoring_events_team_id` ON `ScoringEvents`',
      'DROP INDEX IF EXISTS `scoring_events_user_id` ON `ScoringEvents`',
      
      'DROP INDEX IF EXISTS `user_labs_lab_id` ON `UserLabs`',
      'DROP INDEX IF EXISTS `user_labs_user_id` ON `UserLabs`',
      'DROP INDEX IF EXISTS `user_labs_user_id_lab_id` ON `UserLabs`',
      
      'DROP INDEX IF EXISTS `web_lab_completions_completed_at` ON `WebLabCompletions`',
      'DROP INDEX IF EXISTS `web_lab_completions_lab_id` ON `WebLabCompletions`',
      'DROP INDEX IF EXISTS `web_lab_completions_user_id` ON `WebLabCompletions`',
      'DROP INDEX IF EXISTS `web_lab_completions_user_id_lab_id` ON `WebLabCompletions`',
      
      'DROP INDEX IF EXISTS `web_labs_lab_id` ON `WebLabs`',
      
      'DROP INDEX IF EXISTS `flag_submissions_is_correct` ON `FlagSubmissions`',
      'DROP INDEX IF EXISTS `flag_submissions_lab_id` ON `FlagSubmissions`',
      'DROP INDEX IF EXISTS `flag_submissions_submission_time` ON `FlagSubmissions`',
      'DROP INDEX IF EXISTS `flag_submissions_user_id` ON `FlagSubmissions`',
      'DROP INDEX IF EXISTS `flag_submissions_user_id_lab_id_is_correct` ON `FlagSubmissions`'
    ];

    console.log('Removing additional indexes...\n');
    let removed = 0;
    for (const dropQuery of additionalDrops) {
      try {
        await sequelize.query(dropQuery);
        const indexName = dropQuery.match(/`([^`]+)`/)[1];
        console.log(`✅ Removed: ${indexName}`);
        removed++;
      } catch (error) {
        if (!error.message.includes("check that it exists") && !error.message.includes("needed in a foreign key constraint")) {
          const indexName = dropQuery.match(/`([^`]+)`/)[1];
          console.log(`⚠️  ${indexName}: ${error.message.substring(0, 50)}...`);
        }
      }
    }

    console.log(`\n${removed} additional indexes removed!\n`);

    // Check current count
    const [currentResults] = await sequelize.query(`
      SELECT COUNT(*) as total_indexes
      FROM INFORMATION_SCHEMA.STATISTICS 
      WHERE TABLE_SCHEMA = 'cyberrangev3';
    `);

    console.log(`Current total indexes: ${currentResults[0].total_indexes}`);
    
    if (currentResults[0].total_indexes <= 64) {
      console.log('✅ SUCCESS! Index count is now under the MySQL limit!');
    } else {
      console.log(`Still need to remove ${currentResults[0].total_indexes - 64} more indexes.`);
      
      // If still over limit, show remaining indexes so we can manually choose what to drop
      const [remaining] = await sequelize.query(`
        SELECT 
          TABLE_NAME, 
          INDEX_NAME, 
          NON_UNIQUE,
          COUNT(*) as column_count
        FROM INFORMATION_SCHEMA.STATISTICS 
        WHERE TABLE_SCHEMA = 'cyberrangev3' 
        GROUP BY TABLE_NAME, INDEX_NAME, NON_UNIQUE
        ORDER BY TABLE_NAME, INDEX_NAME;
      `);
      
      console.log('\nRemaining indexes:');
      remaining.forEach(row => {
        console.log(`  ${row.TABLE_NAME}.${row.INDEX_NAME} (${row.column_count} columns)`);
      });
    }

  } catch (error) {
    console.error('Error during final cleanup:', error);
  } finally {
    await sequelize.close();
    process.exit(0);
  }
}

finalIndexCleanup();

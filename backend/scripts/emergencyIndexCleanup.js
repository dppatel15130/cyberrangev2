const mysql = require('mysql2/promise');

async function emergencyIndexCleanup() {
  let connection;
  
  try {
    console.log('=== Emergency MySQL Index Cleanup ===\n');
    
    // Database connection
    connection = await mysql.createConnection({
      host: 'localhost',
      user: 'root',
      password: 'kali',
      database: 'cyberrangev3'
    });

    // Get all indexes
    const [indexes] = await connection.execute(`
      SELECT 
        TABLE_NAME,
        INDEX_NAME,
        COLUMN_NAME,
        SEQ_IN_INDEX
      FROM INFORMATION_SCHEMA.STATISTICS 
      WHERE TABLE_SCHEMA = 'cyberrange'
      ORDER BY TABLE_NAME, INDEX_NAME, SEQ_IN_INDEX
    `);

    console.log(`Found ${indexes.length} total indexes`);

    // Group indexes by table and name
    const indexGroups = {};
    indexes.forEach(index => {
      const key = `${index.TABLE_NAME}.${index.INDEX_NAME}`;
      if (!indexGroups[key]) {
        indexGroups[key] = [];
      }
      indexGroups[key].push(index);
    });

    // Find duplicate indexes (same table, same columns, different names)
    const duplicates = [];
    const processed = new Set();

    Object.keys(indexGroups).forEach(indexKey => {
      if (processed.has(indexKey)) return;
      
      const [tableName, indexName] = indexKey.split('.');
      const columns = indexGroups[indexKey].map(idx => idx.COLUMN_NAME).join(',');
      
      // Find other indexes with same columns
      const similarIndexes = Object.keys(indexGroups).filter(otherKey => {
        if (otherKey === indexKey) return false;
        const [otherTable, otherIndex] = otherKey.split('.');
        if (otherTable !== tableName) return false;
        
        const otherColumns = indexGroups[otherKey].map(idx => idx.COLUMN_NAME).join(',');
        return otherColumns === columns;
      });

      if (similarIndexes.length > 0) {
        // Keep the first one, mark others for deletion
        similarIndexes.forEach(dupKey => {
          if (!processed.has(dupKey)) {
            duplicates.push(dupKey);
            processed.add(dupKey);
          }
        });
        processed.add(indexKey);
      }
    });

    console.log(`Found ${duplicates.length} duplicate indexes to remove`);

    // Remove duplicate indexes
    let removedCount = 0;
    for (const duplicateKey of duplicates) {
      const [tableName, indexName] = duplicateKey.split('.');
      
      // Skip PRIMARY keys
      if (indexName === 'PRIMARY') continue;
      
      try {
        await connection.execute(`DROP INDEX \`${indexName}\` ON \`${tableName}\``);
        console.log(`✅ Removed: ${duplicateKey}`);
        removedCount++;
      } catch (error) {
        console.log(`⚠️  Failed to remove ${duplicateKey}: ${error.message}`);
      }
    }

    // Remove numbered duplicates (name_1, name_2, etc.)
    const numberedDuplicates = Object.keys(indexGroups).filter(key => {
      const [tableName, indexName] = key.split('.');
      return indexName.match(/^(name|email|username)_\d+$/);
    });

    console.log(`\nRemoving ${numberedDuplicates.length} numbered duplicates...`);
    
    for (const numberedKey of numberedDuplicates) {
      const [tableName, indexName] = numberedKey.split('.');
      
      try {
        await connection.execute(`DROP INDEX \`${indexName}\` ON \`${tableName}\``);
        console.log(`✅ Removed: ${numberedKey}`);
        removedCount++;
      } catch (error) {
        console.log(`⚠️  Failed to remove ${numberedKey}: ${error.message}`);
      }
    }

    // Get final count
    const [finalIndexes] = await connection.execute(`
      SELECT COUNT(*) as count
      FROM INFORMATION_SCHEMA.STATISTICS 
      WHERE TABLE_SCHEMA = 'cyberrange'
    `);

    console.log(`\n=== Cleanup Complete ===`);
    console.log(`Removed ${removedCount} indexes`);
    console.log(`Final total: ${finalIndexes[0].count} indexes`);
    
    if (finalIndexes[0].count <= 64) {
      console.log('✅ Index count is now under MySQL limit!');
    } else {
      console.log(`❌ Still ${finalIndexes[0].count - 64} indexes over limit`);
    }

  } catch (error) {
    console.error('Error during emergency cleanup:', error);
  } finally {
    if (connection) {
      await connection.end();
    }
    process.exit(0);
  }
}

emergencyIndexCleanup();

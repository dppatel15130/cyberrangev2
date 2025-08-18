const { sequelize } = require('./config/db');
const { Match } = require('./models');

async function testConnection() {
  try {
    // Test the database connection
    await sequelize.authenticate();
    console.log('✅ Database connection has been established successfully.');
    
    // Test the Match model
    console.log('\n🔍 Testing Match model...');
    const matchCount = await Match.count();
    console.log(`✅ Match model is working. Found ${matchCount} matches in the database.`);
    
    // Show the table structure
    const tableInfo = await sequelize.getQueryInterface().describeTable('Matches');
    console.log('\n📊 Match table structure:', Object.keys(tableInfo));
    
    // Try to create a test match
    console.log('\n🧪 Creating a test match...');
    const testMatch = await Match.create({
      name: 'Test Match ' + Date.now(),
      matchType: 'attack_defend',
      duration: 3600,
      maxTeams: 4,
      status: 'setup',
      createdBy: 1 // Assuming user ID 1 exists
    });
    
    console.log('✅ Test match created successfully:', testMatch.toJSON());
    
  } catch (error) {
    console.error('❌ Error:', error);
    if (error.name === 'SequelizeDatabaseError') {
      console.error('Database Error Details:', error.original);
    }
  } finally {
    // Close the database connection
    await sequelize.close();
    process.exit(0);
  }
}

testConnection();

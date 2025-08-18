const { sequelize } = require('./config/db');
const Match = require('./models/Match');
const Team = require('./models/Team');
const ScoringEvent = require('./models/ScoringEvent');

async function syncDatabase() {
  try {
    console.log('Starting database synchronization...');
    
    // Test the connection
    await sequelize.authenticate();
    console.log('Database connection has been established successfully.');
    
    // Sync all models
    await sequelize.sync({ force: true }); // WARNING: This will drop existing tables and recreate them
    
    console.log('Database synchronized successfully.');
  } catch (error) {
    console.error('Error synchronizing database:', error);
  } finally {
    await sequelize.close();
    process.exit(0);
  }
}

syncDatabase();

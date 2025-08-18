const { sequelize } = require('./config/db');
const Umzug = require('umzug');
const path = require('path');

async function runMigrations() {
  try {
    console.log('Starting database migration...');
    
    const umzug = new Umzug({
      migrations: {
        path: path.join(__dirname, 'migrations'),
        params: [
          sequelize.getQueryInterface(),
          sequelize.constructor,
          () => {
            throw new Error('Migration tried to use old style "done" callback. Please upgrade to "umzug" and return a promise instead.');
          },
        ],
      },
      storage: 'sequelize',
      storageOptions: {
        sequelize: sequelize,
      },
    });

    // Check which migrations have already been run
    const migrations = await umzug.pending();
    console.log('Pending migrations:', migrations.map(m => m.file));

    if (migrations.length === 0) {
      console.log('No pending migrations.');
      return;
    }

    // Run all pending migrations
    console.log('Running migrations...');
    await umzug.up();
    
    console.log('Migration completed successfully!');
  } catch (error) {
    console.error('Migration failed:', error);
    process.exit(1);
  } finally {
    await sequelize.close();
  }
}

runMigrations();

const { sequelize } = require('./config/db');
const { Umzug } = require('umzug');
const path = require('path');

async function runMigrations() {
  try {
    console.log('Starting database migration...');
    
    const umzug = new Umzug({
      migrations: {
        glob: path.join(__dirname, 'migrations', '*.js'),
        resolve: ({ name, path, context }) => {
          const migration = require(path);
          return {
            name,
            up: async () => migration.up(context.queryInterface, context.sequelize.constructor),
            down: async () => migration.down(context.queryInterface, context.sequelize.constructor),
          };
        },
      },
      context: { queryInterface: sequelize.getQueryInterface(), sequelize },
      storage: {
        async executed() {
          const [results] = await sequelize.query(
            "SELECT name FROM SequelizeMeta WHERE name IN (SELECT name FROM SequelizeMeta ORDER BY name ASC)"
          );
          return results.map(result => result.name);
        },
        async logMigration({ name }) {
          await sequelize.query('INSERT INTO SequelizeMeta (name) VALUES (?)', {
            replacements: [name],
          });
        },
        async unlogMigration({ name }) {
          await sequelize.query('DELETE FROM SequelizeMeta WHERE name = ?', {
            replacements: [name],
          });
        },
      },
    });

    // Check which migrations have already been run
    const migrations = await umzug.pending();
    console.log('Pending migrations:', migrations.map(m => m.name));

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

const { Sequelize } = require('sequelize');

const sequelize = new Sequelize(
  process.env.DB_NAME || 'cyberrangev3',
  process.env.DB_USER || 'root',
  process.env.DB_PASSWORD || 'kali',
  {
    host: process.env.DB_HOST || 'localhost',
    port: process.env.DB_PORT || 3306,
    dialect: 'mysql',
    logging: false, // Set to console.log to see SQL queries
    pool: {
      max: 5,
      min: 0,
      acquire: 30000,
      idle: 10000
    }
  }
);

const connectDB = async () => {
  try {
    await sequelize.authenticate();
    console.log('MySQL Connected successfully.');
    
    // Sync models with database (safe alter)
    console.log('Synchronizing database...');
    await sequelize.sync({ alter: true });
    console.log('Database synchronized successfully.');
    
    return sequelize;
  } catch (error) {
    console.error(`Error connecting to MySQL: ${error.message}`);
    process.exit(1);
  }
};

module.exports = { connectDB, sequelize };
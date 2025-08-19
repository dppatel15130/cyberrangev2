#!/usr/bin/env node

/**
 * Database Initialization Script for CyberRange Platform
 * This script initializes the database with all required tables and relationships
 */

const { connectDB, sequelize } = require('../config/db');
const { initializeAdmin } = require('../controllers/authController');

// Import all models to ensure associations are loaded
const User = require('../models/User');
const Team = require('../models/Team');
const Match = require('../models/Match');
const Lab = require('../models/Lab');
const VM = require('../models/VM');
const ScoringEvent = require('../models/ScoringEvent');
const FlagSubmission = require('../models/FlagSubmission');
const WebLab = require('../models/WebLab');
const WebLabCompletion = require('../models/WebLabCompletion');

// Color scheme for console output
const colors = {
  green: '\x1b[32m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  cyan: '\x1b[36m',
  reset: '\x1b[0m'
};

function log(message, color = 'reset') {
  console.log(`${colors[color]}${message}${colors.reset}`);
}

async function initializeDatabase() {
  try {
    log('🚀 Starting CyberRange Database Initialization...', 'blue');
    
    // Step 1: Connect to database
    log('\n📡 Connecting to MySQL database...', 'cyan');
    await connectDB();
    log('✅ Database connection established', 'green');

    // Step 2: Sync database schema
    log('\n🔧 Synchronizing database schema...', 'cyan');
    await sequelize.sync({ force: false, alter: true });
    log('✅ Database schema synchronized', 'green');

    // Step 3: Create default admin user
    log('\n👤 Creating default admin user...', 'cyan');
    await initializeAdmin();
    log('✅ Default admin user created/verified', 'green');

    // Step 4: Create sample data for development/testing
    if (process.env.NODE_ENV === 'development') {
      log('\n📝 Creating sample data for development...', 'cyan');
      await createSampleData();
      log('✅ Sample data created', 'green');
    }

    // Step 5: Verify all tables exist
    log('\n🔍 Verifying database tables...', 'cyan');
    await verifyTables();
    log('✅ All tables verified', 'green');

    log('\n🎉 Database initialization completed successfully!', 'green');
    log('\n📊 Database Summary:', 'blue');
    
    const tables = await sequelize.getQueryInterface().showAllTables();
    log(`   Total Tables: ${tables.length}`, 'cyan');
    
    tables.forEach(table => {
      log(`   - ${table}`, 'cyan');
    });

    log('\n🔐 Default Admin Credentials:', 'yellow');
    log('   Username: admin', 'yellow');
    log('   Password: admin123', 'yellow');
    log('   Please change the password after first login!', 'red');

    process.exit(0);

  } catch (error) {
    log(`\n❌ Database initialization failed: ${error.message}`, 'red');
    console.error(error);
    process.exit(1);
  }
}

async function createSampleData() {
  try {
    // Create sample teams
    const team1 = await Team.findOrCreate({
      where: { name: 'Red Hawks' },
      defaults: {
        name: 'Red Hawks',
        description: 'Elite red team specialists',
        color: '#DC3545',
        maxMembers: 4,
        currentPoints: 0,
        createdBy: 1,
        networkSegment: '172.16.200.0/28'
      }
    });

    const team2 = await Team.findOrCreate({
      where: { name: 'Blue Guardians' },
      defaults: {
        name: 'Blue Guardians',
        description: 'Defensive security experts',
        color: '#007BFF',
        maxMembers: 4,
        currentPoints: 0,
        createdBy: 1,
        networkSegment: '172.16.210.0/28'
      }
    });

    // Create sample match
    const match = await Match.findOrCreate({
      where: { name: 'Sample Cyber Warfare Exercise' },
      defaults: {
        name: 'Sample Cyber Warfare Exercise',
        description: 'A comprehensive red vs blue team exercise with vulnerable Windows 7 targets',
        status: 'setup',
        matchType: 'attack_defend',
        maxTeams: 4,
        currentTeams: 2,
        duration: 7200, // 2 hours
        scoringRules: {
          flagCapture: 100,
          serviceHijack: 50,
          vulnerabilityExploit: 75,
          defensePoints: 25,
          timeBonus: 10,
          penalties: {
            downtime: -20,
            cheating: -100
          }
        },
        flags: [
          {
            id: 'flag-001',
            name: 'Administrator Access',
            description: 'Gain administrator access to the target system',
            points: 150,
            category: 'privilege_escalation'
          },
          {
            id: 'flag-002',
            name: 'Sensitive Data Access',
            description: 'Access sensitive files in the Documents folder',
            points: 100,
            category: 'data_exfiltration'
          },
          {
            id: 'flag-003',
            name: 'Network Persistence',
            description: 'Establish persistent network access',
            points: 125,
            category: 'persistence'
          }
        ],
        createdBy: 1,
        packetCaptureEnabled: true,
        logAnalysisEnabled: true,
        elkIntegration: true,
        autoScoring: true
      }
    });

    // Create sample labs
    const lab = await Lab.findOrCreate({
      where: { name: 'Windows 7 Vulnerability Assessment' },
      defaults: {
        name: 'Windows 7 Vulnerability Assessment',
        description: 'Assess and exploit vulnerabilities in a Windows 7 SP1 system',
        difficulty: 'intermediate',
        category: 'penetration-testing',
        estimatedTime: 120,
        maxAttempts: 3,
        autoGrading: true,
        isActive: true,
        objectives: [
          'Identify system vulnerabilities',
          'Exploit identified vulnerabilities',
          'Escalate privileges to administrator',
          'Maintain persistent access'
        ],
        requirements: [
          'Basic knowledge of Windows systems',
          'Familiarity with penetration testing tools',
          'Understanding of network protocols'
        ],
        createdBy: 1
      }
    });

    // Create sample VMs
    const vm1 = await VM.findOrCreate({
      where: { name: 'Windows-Target-01' },
      defaults: {
        name: 'Windows-Target-01',
        description: 'Vulnerable Windows 7 SP1 x64 target system',
        proxmoxId: 103,
        ipAddress: '172.16.200.150',
        username: 'administrator',
        password: 'password123',
        operatingSystem: 'Windows 7 SP1 x64',
        isTemplate: false,
        status: 'stopped',
        assignedTo: null,
        createdBy: 1,
        vulnerabilities: [
          'MS17-010 (EternalBlue)',
          'MS08-067 (Conficker)',
          'Weak passwords',
          'Unpatched services'
        ]
      }
    });

    const vm2 = await VM.findOrCreate({
      where: { name: 'Kali-Attacker-01' },
      defaults: {
        name: 'Kali-Attacker-01',
        description: 'Kali Linux 2024.2 attacker workstation',
        proxmoxId: 104,
        ipAddress: '172.16.200.151',
        username: 'kali',
        password: 'kali',
        operatingSystem: 'Kali Linux 2024.2',
        isTemplate: false,
        status: 'stopped',
        assignedTo: null,
        createdBy: 1,
        tools: [
          'Metasploit Framework',
          'Nmap',
          'Wireshark',
          'Burp Suite',
          'SQLMap',
          'John the Ripper'
        ]
      }
    });

    log('   ✅ Sample teams created', 'green');
    log('   ✅ Sample match created', 'green');
    log('   ✅ Sample lab created', 'green');
    log('   ✅ Sample VMs created', 'green');

  } catch (error) {
    log(`   ❌ Error creating sample data: ${error.message}`, 'red');
    throw error;
  }
}

async function verifyTables() {
  const expectedTables = [
    'Users',
    'Teams',
    'Matches',
    'Labs',
    'VMs',
    'ScoringEvents',
    'FlagSubmissions',
    'WebLabs',
    'WebLabCompletions'
  ];

  const actualTables = await sequelize.getQueryInterface().showAllTables();
  
  for (const table of expectedTables) {
    if (actualTables.includes(table)) {
      log(`   ✅ ${table} table exists`, 'green');
    } else {
      log(`   ❌ ${table} table missing`, 'red');
      throw new Error(`Required table ${table} is missing`);
    }
  }

  // Verify table relationships by running test queries
  try {
    await User.findAll({ limit: 1 });
    await Team.findAll({ limit: 1 });
    await Match.findAll({ limit: 1, include: [{ model: Team, as: 'teams' }] });
    await ScoringEvent.findAll({ limit: 1 });
    log('   ✅ Table relationships verified', 'green');
  } catch (error) {
    log(`   ❌ Table relationship error: ${error.message}`, 'red');
    throw error;
  }
}

// Handle script execution
if (require.main === module) {
  log('CyberRange Database Initialization Script', 'blue');
  log('==========================================', 'blue');
  
  // Check if MySQL is running
  const mysql = require('mysql2/promise');
  
  (async () => {
    try {
      // Test MySQL connection first
      const connection = await mysql.createConnection({
        host: process.env.DB_HOST || '127.0.0.1',
        port: process.env.DB_PORT || 3306,
        user: process.env.DB_USER || 'root',
        password: process.env.DB_PASSWORD || 'kali'
      });
      
      // Create database if it doesn't exist
      const dbName = process.env.DB_NAME || 'cyberrangev3';
      await connection.execute(`CREATE DATABASE IF NOT EXISTS \`${dbName}\``);
      await connection.end();
      
      log(`✅ Database '${dbName}' ready`, 'green');
      
      // Initialize the database
      await initializeDatabase();
      
    } catch (error) {
      log(`❌ MySQL connection failed: ${error.message}`, 'red');
      log('\n🔧 Please ensure MySQL is running and credentials are correct:', 'yellow');
      log(`   Host: ${process.env.DB_HOST || '127.0.0.1'}`, 'yellow');
      log(`   Port: ${process.env.DB_PORT || 3306}`, 'yellow');
      log(`   User: ${process.env.DB_USER || 'root'}`, 'yellow');
      log(`   Database: ${process.env.DB_NAME || 'cyberrangev3'}`, 'yellow');
      process.exit(1);
    }
  })();
}

module.exports = { initializeDatabase, createSampleData, verifyTables };

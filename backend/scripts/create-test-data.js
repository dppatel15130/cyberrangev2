const { Match, Team, User } = require('../models');
const { sequelize } = require('../config/db');

async function createTestData() {
  try {
    console.log('🔧 Creating test data for cyberwar competition...\n');

    // Test database connection
    await sequelize.authenticate();
    console.log('✅ Database connection established');

    // Get or create admin user
    let adminUser = await User.findOne({ where: { role: 'admin' } });
    if (!adminUser) {
      console.log('❌ No admin user found. Please create an admin user first.');
      return;
    }
    console.log(`✅ Using admin user: ${adminUser.username}`);

    // Create test teams
    console.log('\n👥 Creating test teams...');
    
    const teams = [
      {
        name: 'AlphaTeam',
        description: 'Elite cybersecurity team',
        color: '#007bff',
        maxMembers: 4,
        createdBy: adminUser.id
      },
      {
        name: 'BetaSquad',
        description: 'Red team specialists',
        color: '#dc3545',
        maxMembers: 4,
        createdBy: adminUser.id
      },
      {
        name: 'GammaForce',
        description: 'Blue team defenders',
        color: '#28a745',
        maxMembers: 4,
        createdBy: adminUser.id
      }
    ];

    const createdTeams = [];
    for (const teamData of teams) {
      const existingTeam = await Team.findOne({ where: { name: teamData.name } });
      if (!existingTeam) {
        const team = await Team.create(teamData);
        createdTeams.push(team);
        console.log(`  ✅ Created team: ${team.name}`);
      } else {
        createdTeams.push(existingTeam);
        console.log(`  ℹ️  Team already exists: ${existingTeam.name}`);
      }
    }

    // Add admin user to all teams
    console.log('\n🔗 Adding admin user to teams...');
    for (const team of createdTeams) {
      await team.addMember(adminUser.id);
      console.log(`  ✅ Added ${adminUser.username} to ${team.name}`);
    }

    // Create test matches
    console.log('\n🎮 Creating test matches...');
    
    const matches = [
      {
        name: 'SQL Injection Challenge',
        description: 'Test your SQL injection skills against vulnerable web applications',
        matchType: 'attack_defend',
        maxTeams: 4,
        duration: 7200, // 2 hours
        status: 'setup',
        createdBy: adminUser.id,
        scoringRules: JSON.stringify({
          flagCapture: 100,
          serviceHijack: 50,
          vulnerabilityExploit: 25,
          defensePoints: 10,
          timeBonus: 5,
          penalties: {
            downtime: -20,
            cheating: -100
          }
        })
      },
      {
        name: 'Network Penetration',
        description: 'Penetrate the network and capture flags',
        matchType: 'capture_flag',
        maxTeams: 4,
        duration: 5400, // 1.5 hours
        status: 'setup',
        createdBy: adminUser.id,
        scoringRules: JSON.stringify({
          flagCapture: 100,
          serviceHijack: 50,
          vulnerabilityExploit: 25,
          defensePoints: 10,
          timeBonus: 5,
          penalties: {
            downtime: -20,
            cheating: -100
          }
        })
      },
      {
        name: 'Red vs Blue',
        description: 'Classic red team vs blue team competition',
        matchType: 'red_vs_blue',
        maxTeams: 2,
        duration: 3600, // 1 hour
        status: 'setup',
        createdBy: adminUser.id,
        scoringRules: JSON.stringify({
          flagCapture: 100,
          serviceHijack: 50,
          vulnerabilityExploit: 25,
          defensePoints: 10,
          timeBonus: 5,
          penalties: {
            downtime: -20,
            cheating: -100
          }
        })
      }
    ];

    const createdMatches = [];
    for (const matchData of matches) {
      const existingMatch = await Match.findOne({ where: { name: matchData.name } });
      if (!existingMatch) {
        const match = await Match.create(matchData);
        createdMatches.push(match);
        console.log(`  ✅ Created match: ${match.name}`);
      } else {
        createdMatches.push(existingMatch);
        console.log(`  ℹ️  Match already exists: ${existingMatch.name}`);
      }
    }

    // Assign teams to matches
    console.log('\n🔗 Assigning teams to matches...');
    
    for (let i = 0; i < createdMatches.length && i < createdTeams.length; i++) {
      const match = createdMatches[i];
      const team = createdTeams[i];
      
      await match.addTeam(team);
      console.log(`  ✅ Assigned ${team.name} to ${match.name}`);
    }

    // Update match status to 'waiting' for matches with teams
    console.log('\n🚀 Updating match status...');
    
    for (const match of createdMatches) {
      const updatedMatch = await Match.findByPk(match.id, {
        include: [
          {
            model: Team,
            as: 'teams',
            through: { attributes: [] }
          }
        ]
      });

      if (updatedMatch.teams.length > 0) {
        await updatedMatch.update({ 
          status: 'waiting',
          currentTeams: updatedMatch.teams.length
        });
        console.log(`  ✅ ${updatedMatch.name} is now waiting with ${updatedMatch.teams.length} teams`);
      }
    }

    // Start the first match as active
    const firstMatch = await Match.findOne({
      where: { status: 'waiting' },
      include: [
        {
          model: Team,
          as: 'teams',
          through: { attributes: [] }
        }
      ]
    });

    if (firstMatch) {
      await firstMatch.update({ 
        status: 'active',
        startTime: new Date()
      });
      console.log(`\n🎯 Started match "${firstMatch.name}" as active!`);
    }

    // Final status report
    console.log('\n📊 Final Status Report:');
    const finalMatches = await Match.findAll({
      include: [
        {
          model: Team,
          as: 'teams',
          through: { attributes: [] }
        }
      ],
      order: [['status', 'ASC'], ['id', 'ASC']]
    });

    finalMatches.forEach(match => {
      console.log(`  - ${match.name}: ${match.status} (${match.teams.length} teams)`);
    });

    console.log('\n✅ Test data creation completed successfully!');
    console.log('\n🎮 Next steps:');
    console.log('  1. Users can now view matches in the lobby');
    console.log('  2. Teams can participate in active matches');
    console.log('  3. Use admin dashboard to manage matches');

  } catch (error) {
    console.error('❌ Error creating test data:', error);
    console.error('Error details:', error.message);
  } finally {
    try {
      if (sequelize) {
        await sequelize.close();
        console.log('✅ Database connection closed');
      }
    } catch (closeError) {
      console.log('⚠️  Error closing database connection:', closeError.message);
    }
  }
}

// Run the setup
createTestData();

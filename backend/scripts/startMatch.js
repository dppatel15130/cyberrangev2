const { Match, Team, User } = require('../models');
const gameEngine = require('../services/gameEngine');

async function startMatch() {
  try {
    console.log('=== Starting Cyber Warfare Match ===\n');

    const matchId = 3;
    const match = await Match.findByPk(matchId, {
      include: [
        {
          model: Team,
          as: 'teams',
          include: [
            {
              model: User,
              as: 'members',
              attributes: ['id', 'username', 'email']
            }
          ]
        }
      ]
    });

    if (!match) {
      console.log('❌ Match 3 not found');
      return;
    }

    console.log('🎯 MATCH DETAILS:');
    console.log(`  ID: ${match.id}`);
    console.log(`  Name: ${match.name}`);
    console.log(`  Current Status: ${match.status}`);
    console.log(`  Teams: ${match.teams.length}/${match.maxTeams}`);

    if (match.status === 'active') {
      console.log('✅ Match is already active!');
      return;
    }

    if (match.teams.length < 2) {
      console.log('❌ Need at least 2 teams to start the match');
      console.log(`Current teams: ${match.teams.length}`);
      return;
    }

    console.log('\n👥 TEAMS READY:');
    match.teams.forEach(team => {
      console.log(`  ${team.name} (ID: ${team.id}):`);
      console.log(`    Members: ${team.members.map(m => m.username).join(', ')}`);
    });

    console.log('\n🚀 STARTING MATCH...');
    
    // Update match status to active
    await match.update({
      status: 'active',
      startTime: new Date(),
      actualStartTime: new Date()
    });

    console.log('✅ Match status updated to active');

    // Start the game engine
    try {
      console.log('🎮 Starting game engine...');
      await gameEngine.startMatch(matchId);
      console.log('✅ Game engine started successfully');
    } catch (gameError) {
      console.warn('⚠️  Game engine error (continuing):', gameError.message);
    }

    // Update final status
    const updatedMatch = await Match.findByPk(matchId, {
      include: [
        {
          model: Team,
          as: 'teams',
          include: [
            {
              model: User,
              as: 'members',
              attributes: ['id', 'username']
            }
          ]
        }
      ]
    });

    console.log('\n🎉 MATCH STARTED SUCCESSFULLY!');
    console.log(`Status: ${updatedMatch.status}`);
    console.log(`Start Time: ${updatedMatch.startTime}`);
    console.log(`Teams: ${updatedMatch.teams.length}`);

    console.log('\n🏆 COMPETITION IS NOW LIVE!');
    console.log('Teams can now:');
    console.log('1. Access their attacker VMs (172.16.200.136)');
    console.log('2. Target the vulnerable server (172.16.26.139)');
    console.log('3. Use Guacamole to access target: http://172.16.200.136:8080/guacamole');
    console.log('4. Find vulnerabilities and capture flags');
    console.log('5. Earn points through automated scoring');

    console.log('\n📊 MONITORING:');
    console.log('- Real-time scoring updates');
    console.log('- ELK stack integration for logs');
    console.log('- Automated vulnerability detection');
    console.log('- Live leaderboard updates');

    console.log('\n=== Match Started Successfully ===');

  } catch (error) {
    console.error('Error starting match:', error);
  } finally {
    process.exit(0);
  }
}

startMatch();

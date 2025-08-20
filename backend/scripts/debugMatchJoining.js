const { Match, Team, User } = require('../models');

async function debugMatchJoining() {
  try {
    console.log('=== Debugging Match Joining Issue ===\n');

    // Check Match 3
    const match = await Match.findByPk(3, {
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
    console.log(`  Status: ${match.status}`);
    console.log(`  Max Teams: ${match.maxTeams}`);
    console.log(`  Current Teams: ${match.currentTeams}`);

    console.log('\n👥 TEAMS IN MATCH:');
    match.teams.forEach(team => {
      console.log(`  ${team.name} (ID: ${team.id}):`);
      console.log(`    Members: ${team.members.map(m => m.username).join(', ')}`);
      console.log(`    Status: ${team.isActive ? 'Active' : 'Inactive'}`);
    });

    // Check if teams are already in match
    const redTeam = await Team.findByPk(2);
    const blueTeam = await Team.findByPk(3);

    if (redTeam) {
      const redInMatch = await match.hasTeam(redTeam);
      console.log(`\nRedTeam (ID: 2) in match: ${redInMatch ? '✅ Yes' : '❌ No'}`);
    }

    if (blueTeam) {
      const blueInMatch = await match.hasTeam(blueTeam);
      console.log(`BlueTeam (ID: 3) in match: ${blueInMatch ? '✅ Yes' : '❌ No'}`);
    }

    // Check current user
    const adminUser = await User.findOne({ where: { email: 'admin@gmail.com' } });
    if (adminUser) {
      console.log(`\n👤 CURRENT USER: ${adminUser.username} (ID: ${adminUser.id})`);
      
      // Check which teams the user is a member of
      const userTeams = await adminUser.getTeams();
      console.log('User teams:');
      userTeams.forEach(team => {
        console.log(`  - ${team.name} (ID: ${team.id})`);
      });
    }

    console.log('\n🔍 DIAGNOSIS:');
    if (match.teams.length >= match.maxTeams) {
      console.log('❌ Match is at maximum capacity - no more teams can join');
      console.log('💡 SOLUTION: Start the match or remove a team first');
    } else if (match.status !== 'waiting' && match.status !== 'setup') {
      console.log('❌ Match is not accepting new teams');
      console.log('💡 SOLUTION: Match status needs to be "waiting" or "setup"');
    } else {
      console.log('✅ Match should accept new teams');
      console.log('💡 The 400 error might be because the team is already in the match');
    }

    console.log('\n🚀 RECOMMENDED ACTIONS:');
    console.log('1. If you want to start the match: Use admin dashboard to start match 3');
    console.log('2. If you want to remove teams: Use admin dashboard to remove teams');
    console.log('3. If you want to join with a different team: Create a new team');
    console.log('4. If you want to test joining: Remove a team first, then try joining');

  } catch (error) {
    console.error('Error debugging match joining:', error);
  } finally {
    process.exit(0);
  }
}

debugMatchJoining();

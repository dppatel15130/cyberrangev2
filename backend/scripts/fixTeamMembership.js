const { Team, User, Match } = require('../models');

async function fixTeamMembership() {
  try {
    console.log('=== Fixing Team Membership Issues ===\n');

    // Get admin user
    const adminUser = await User.findOne({ where: { email: 'admin@gmail.com' } });
    if (!adminUser) {
      console.log('❌ Admin user not found');
      return;
    }
    console.log(`✅ Found admin user: ${adminUser.username}`);

    // Get teams
    const redTeam = await Team.findOne({ where: { name: 'RedTeam' } });
    const blueTeam = await Team.findOne({ where: { name: 'BlueTeam' } });

    if (!redTeam || !blueTeam) {
      console.log('❌ Teams not found');
      return;
    }

    console.log(`✅ Found RedTeam (ID: ${redTeam.id})`);
    console.log(`✅ Found BlueTeam (ID: ${blueTeam.id})`);

    // Add admin to BlueTeam if not already a member
    const blueTeamMembers = await blueTeam.getMembers();
    if (blueTeamMembers.length === 0) {
      await blueTeam.addMember(adminUser);
      console.log('✅ Added admin to BlueTeam');
    } else {
      console.log('ℹ️  BlueTeam already has members');
    }

    // Check match status
    const match = await Match.findByPk(3);
    if (match) {
      console.log(`\n=== Match Status ===`);
      console.log(`Match ID: ${match.id}`);
      console.log(`Name: ${match.name}`);
      console.log(`Status: ${match.status}`);
      console.log(`Max Teams: ${match.maxTeams}`);
      
      const matchTeams = await match.getTeams();
      console.log(`Current Teams: ${matchTeams.length}`);
      matchTeams.forEach(team => {
        console.log(`  - ${team.name} (ID: ${team.id})`);
      });

      // If match is not active, we can add teams
      if (match.status === 'waiting' || match.status === 'setup') {
        console.log('\n=== Adding Teams to Match ===');
        
        // Add RedTeam if not already in match
        const redTeamInMatch = matchTeams.find(t => t.id === redTeam.id);
        if (!redTeamInMatch) {
          await match.addTeam(redTeam);
          console.log('✅ Added RedTeam to match');
        } else {
          console.log('ℹ️  RedTeam already in match');
        }

        // Add BlueTeam if not already in match
        const blueTeamInMatch = matchTeams.find(t => t.id === blueTeam.id);
        if (!blueTeamInMatch) {
          await match.addTeam(blueTeam);
          console.log('✅ Added BlueTeam to match');
        } else {
          console.log('ℹ️  BlueTeam already in match');
        }

        // Update match status if needed
        const updatedMatchTeams = await match.getTeams();
        if (updatedMatchTeams.length >= 2 && match.status === 'setup') {
          await match.update({ status: 'waiting' });
          console.log('✅ Updated match status to waiting');
        }
      }
    } else {
      console.log('❌ Match 3 not found');
    }

    // Show final team memberships
    console.log('\n=== Final Team Memberships ===');
    
    const finalRedTeam = await Team.findByPk(redTeam.id, {
      include: [{ model: User, as: 'members', attributes: ['id', 'username', 'email'] }]
    });
    console.log(`RedTeam members: ${finalRedTeam.members.map(m => m.username).join(', ')}`);

    const finalBlueTeam = await Team.findByPk(blueTeam.id, {
      include: [{ model: User, as: 'members', attributes: ['id', 'username', 'email'] }]
    });
    console.log(`BlueTeam members: ${finalBlueTeam.members.map(m => m.username).join(', ')}`);

    console.log('\n=== Fix Complete ===');

  } catch (error) {
    console.error('Error fixing team membership:', error);
  } finally {
    process.exit(0);
  }
}

fixTeamMembership();

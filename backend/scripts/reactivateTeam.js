const { Team, User } = require('../models');

async function reactivateTeam() {
  try {
    console.log('=== Reactivating Inactive Teams ===\n');
    
    // Find all inactive teams
    const inactiveTeams = await Team.findAll({
      where: { isActive: false },
      include: [
        {
          model: User,
          as: 'members',
          attributes: ['id', 'username'],
          through: { attributes: [] }
        }
      ]
    });

    console.log(`Found ${inactiveTeams.length} inactive teams:\n`);

    inactiveTeams.forEach(team => {
      console.log(`- ${team.name} (ID: ${team.id}, Members: ${team.members.length})`);
    });

    if (inactiveTeams.length === 0) {
      console.log('No inactive teams found.');
      return;
    }

    // Reactivate all inactive teams
    for (const team of inactiveTeams) {
      await team.update({ isActive: true });
      console.log(`✅ Reactivated team: ${team.name}`);
    }

    console.log('\n=== All inactive teams have been reactivated ===');

  } catch (error) {
    console.error('Error reactivating teams:', error);
  } finally {
    process.exit(0);
  }
}

reactivateTeam();

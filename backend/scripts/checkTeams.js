const { Team, User } = require('../models');

async function checkTeams() {
  try {
    console.log('=== Checking All Teams ===\n');
    
    const teams = await Team.findAll({
      include: [
        {
          model: User,
          as: 'members',
          attributes: ['id', 'username', 'email'],
          through: { attributes: [] }
        }
      ],
      order: [['createdAt', 'DESC']]
    });

    console.log(`Total teams found: ${teams.length}\n`);

    teams.forEach((team, index) => {
      console.log(`${index + 1}. Team: ${team.name}`);
      console.log(`   ID: ${team.id}`);
      console.log(`   Active: ${team.isActive}`);
      console.log(`   Created: ${team.createdAt}`);
      console.log(`   Members: ${team.members.length}/${team.maxMembers}`);
      console.log(`   Members: ${team.members.map(m => m.username).join(', ')}`);
      console.log(`   Color: ${team.color}`);
      console.log(`   Description: ${team.description || 'N/A'}`);
      console.log('');
    });

    // Check for duplicate names
    const teamNames = teams.map(t => t.name);
    const duplicates = teamNames.filter((name, index) => teamNames.indexOf(name) !== index);
    
    if (duplicates.length > 0) {
      console.log('=== DUPLICATE TEAM NAMES FOUND ===');
      duplicates.forEach(name => {
        const duplicateTeams = teams.filter(t => t.name === name);
        console.log(`Name: "${name}" appears ${duplicateTeams.length} times:`);
        duplicateTeams.forEach(team => {
          console.log(`  - ID: ${team.id}, Active: ${team.isActive}, Created: ${team.createdAt}`);
        });
      });
    }

    // Check inactive teams
    const inactiveTeams = teams.filter(t => !t.isActive);
    if (inactiveTeams.length > 0) {
      console.log('=== INACTIVE TEAMS ===');
      inactiveTeams.forEach(team => {
        console.log(`- ${team.name} (ID: ${team.id}, Members: ${team.members.length})`);
      });
    }

    // Check full teams
    const fullTeams = teams.filter(t => t.members.length >= t.maxMembers);
    if (fullTeams.length > 0) {
      console.log('=== FULL TEAMS ===');
      fullTeams.forEach(team => {
        console.log(`- ${team.name} (ID: ${team.id}, Members: ${team.members.length}/${team.maxMembers})`);
      });
    }

  } catch (error) {
    console.error('Error checking teams:', error);
  } finally {
    process.exit(0);
  }
}

checkTeams();

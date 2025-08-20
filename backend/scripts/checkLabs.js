const { Lab } = require('../models');

async function checkLabs() {
  try {
    console.log('=== Checking Labs ===\n');
    
    const labs = await Lab.findAll();
    console.log(`Total labs found: ${labs.length}\n`);

    labs.forEach((lab, index) => {
      console.log(`${index + 1}. Lab: ${lab.name}`);
      console.log(`   ID: ${lab.id}`);
      console.log(`   Description: ${lab.description}`);
      console.log(`   Status: ${lab.status}`);
      console.log('');
    });

    // Create a default lab if none exist
    if (labs.length === 0) {
      console.log('No labs found. Creating default lab...');
      
      const defaultLab = await Lab.create({
        name: 'CyberWar Lab',
        description: 'Default laboratory for cyber warfare matches',
        status: 'active',
        category: 'cyberwar',
        instructions: 'Default cyber warfare laboratory for vulnerability testing and exploitation.',
        createdBy: 1
      });
      
      console.log(`✅ Created default lab with ID: ${defaultLab.id}`);
    } else {
      console.log(`Using existing lab with ID: ${labs[0].id}`);
    }

  } catch (error) {
    console.error('Error checking labs:', error);
  } finally {
    process.exit(0);
  }
}

checkLabs();

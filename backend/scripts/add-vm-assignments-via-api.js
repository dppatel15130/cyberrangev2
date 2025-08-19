const axios = require('axios');
const jwt = require('jsonwebtoken');
const { Match, Team } = require('../models');
const { sequelize } = require('../config/db');

// Configuration
const API_BASE = 'http://localhost:5000/api';
const JWT_SECRET = 'your_jwt_secret_key_here';

async function addVMAssignmentsViaAPI() {
  try {
    console.log('🔧 Adding VM assignments via API to running server...\n');
    
    // Test database connection
    await sequelize.authenticate();
    console.log('✅ Database connection established');

    // Create admin token
    const testUser = {
      id: 1,
      username: 'admin',
      role: 'admin'
    };
    
    const token = jwt.sign(testUser, JWT_SECRET, { expiresIn: '1h' });
    console.log('✅ Generated admin JWT token');

    // Get active matches
    const matches = await Match.findAll({
      where: { status: ['active', 'waiting'] },
      include: [
        {
          model: Team,
          as: 'teams',
          through: { attributes: [] }
        }
      ]
    });

    if (matches.length === 0) {
      console.log('❌ No active or waiting matches found.');
      return;
    }

    console.log(`Found ${matches.length} matches to assign VMs to`);

    for (const match of matches) {
      console.log(`\n📋 Processing match: ${match.name} (ID: ${match.id})`);
      
      if (match.teams.length === 0) {
        console.log('  ⚠️  No teams assigned to this match');
        continue;
      }

      // Assign VMs to each team via API
      for (let i = 0; i < match.teams.length; i++) {
        const team = match.teams[i];
        console.log(`  🎯 Assigning VMs to team: ${team.name} (ID: ${team.id})`);

        // Create VM requirements for this team
        const vmRequirements = [
          { type: 'kali', role: 'attacker', name: `Kali-Attacker-${team.id}` },
          { type: 'windows', role: 'target', name: `Windows-Target-${team.id}` }
        ];

        try {
          // Call the API endpoint to assign VMs
          const response = await axios.post(`${API_BASE}/proxmox/matches/${match.id}/teams/${team.id}/assign`, {
            vmRequirements
          }, {
            headers: {
              'Content-Type': 'application/json',
              'x-auth-token': token
            }
          });
          
          if (response.data.success) {
            console.log(`    ✅ Successfully assigned VMs to ${team.name}`);
            response.data.assignedVMs.forEach(vm => {
              console.log(`      - VM ${vm.vmId}: ${vm.name} (${vm.type}/${vm.role})`);
            });
          } else {
            console.log(`    ❌ Failed to assign VMs to ${team.name}: ${response.data.error}`);
          }
        } catch (error) {
          if (error.response) {
            console.log(`    ❌ API error for ${team.name}: ${error.response.status} - ${error.response.data.error || error.response.data.message}`);
          } else {
            console.log(`    ❌ Network error for ${team.name}: ${error.message}`);
          }
        }
      }
    }

    console.log('\n📊 Verifying assignments...');
    
    // Test the assignments by calling the debug endpoint
    try {
      const debugResponse = await axios.get(`${API_BASE}/proxmox/debug`, {
        headers: {
          'Content-Type': 'application/json',
          'x-auth-token': token
        }
      });
      
      console.log('✅ Server ProxmoxService state:');
      console.log(`  Assignments: ${debugResponse.data.assignmentsSize}`);
      console.log(`  Available VMs: ${debugResponse.data.availableVMsSize}`);
      
      for (const [matchId, assignments] of Object.entries(debugResponse.data.matchAssignments)) {
        if (Object.keys(assignments).length > 0) {
          console.log(`  Match ${matchId}: ${Object.keys(assignments).length} teams with VMs`);
        }
      }
      
    } catch (error) {
      console.log('❌ Failed to verify assignments:', error.message);
    }

    console.log('\n✅ VM assignment via API completed!');

  } catch (error) {
    console.error('❌ Error adding VM assignments via API:', error);
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

addVMAssignmentsViaAPI();


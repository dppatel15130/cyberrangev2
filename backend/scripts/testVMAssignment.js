const vmAssignmentService = require('../services/vmAssignmentService');
const { User, Team, Match, VM } = require('../models');

async function testVMAssignment() {
  try {
    console.log('=== Testing VM Assignment Service ===\n');

    // Step 1: Initialize VM pool
    console.log('1. Initializing VM pool...');
    const initResult = await vmAssignmentService.initializeVMPool();
    if (initResult) {
      console.log('✅ VM pool initialized successfully');
    } else {
      console.log('❌ Failed to initialize VM pool');
      return;
    }

    // Step 2: Get VM pool status
    console.log('\n2. VM Pool Status:');
    const poolStatus = vmAssignmentService.getVMPoolStatus();
    console.log('Total VMs:', poolStatus.total);
    console.log('Available:', poolStatus.available);
    console.log('Assigned:', poolStatus.assigned);
    console.log('By Type:', poolStatus.byType);
    console.log('By Role:', poolStatus.byRole);

    // Step 3: Test VM assignment for existing match
    console.log('\n3. Testing VM assignment for Match 3...');
    const match = await Match.findByPk(3, {
      include: [
        {
          model: Team,
          as: 'teams',
          include: [
            {
              model: User,
              as: 'members'
            }
          ]
        }
      ]
    });

    if (!match) {
      console.log('❌ Match 3 not found');
      return;
    }

    console.log(`Match: ${match.name} (Status: ${match.status})`);
    console.log(`Teams: ${match.teams.length}`);

    // Step 4: Assign VMs to each team
    for (const team of match.teams) {
      console.log(`\n4. Assigning VMs to team: ${team.name}`);
      console.log(`Team members: ${team.members.map(m => m.username).join(', ')}`);

      const vmResult = await vmAssignmentService.assignVMsToTeam(team.id, match.id);
      
      if (vmResult.success) {
        console.log(`✅ Successfully assigned ${vmResult.assignedVMs.length} VMs to team ${team.name}`);
        vmResult.assignedVMs.forEach(vm => {
          console.log(`  - ${vm.name} (${vm.vmId}): ${vm.ipAddress} - ${vm.type}/${vm.role}`);
        });
      } else {
        console.log(`❌ Failed to assign VMs to team ${team.name}:`, vmResult.error);
      }
    }

    // Step 5: Get updated VM pool status
    console.log('\n5. Updated VM Pool Status:');
    const updatedStatus = vmAssignmentService.getVMPoolStatus();
    console.log('Total VMs:', updatedStatus.total);
    console.log('Available:', updatedStatus.available);
    console.log('Assigned:', updatedStatus.assigned);

    // Step 6: Test getting user VMs
    console.log('\n6. Testing user VM retrieval...');
    const adminUser = await User.findOne({ where: { email: 'admin@gmail.com' } });
    if (adminUser) {
      const userVMs = await vmAssignmentService.getUserVMs(adminUser.id, match.id);
      console.log(`User ${adminUser.username} has ${userVMs.length} assigned VMs:`);
      userVMs.forEach(vm => {
        console.log(`  - ${vm.name} (${vm.vmId}): ${vm.ipAddress}`);
      });
    }

    // Step 7: Test getting team VMs
    console.log('\n7. Testing team VM retrieval...');
    for (const team of match.teams) {
      const teamVMs = await vmAssignmentService.getTeamVMs(team.id, match.id);
      console.log(`Team ${team.name} has ${teamVMs.length} assigned VMs:`);
      teamVMs.forEach(vm => {
        console.log(`  - ${vm.name} (${vm.vmId}): ${vm.ipAddress}`);
      });
    }

    console.log('\n=== VM Assignment Test Complete ===');

  } catch (error) {
    console.error('Error testing VM assignment:', error);
  } finally {
    process.exit(0);
  }
}

testVMAssignment();

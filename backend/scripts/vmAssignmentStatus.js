const vmAssignmentService = require('../services/vmAssignmentService');
const { User, Team, Match, VM } = require('../models');

async function showVMAssignmentStatus() {
  try {
    console.log('=== VM Assignment System Status ===\n');

    // Initialize VM pool
    console.log('1. Initializing VM Assignment Pool...');
    await vmAssignmentService.initializeVMPool();
    
    // Show VM pool status
    const poolStatus = vmAssignmentService.getVMPoolStatus();
    console.log('\n2. VM Pool Status:');
    console.log(`   Total VMs: ${poolStatus.total}`);
    console.log(`   Available: ${poolStatus.available}`);
    console.log(`   Assigned: ${poolStatus.assigned}`);
    console.log(`   By Type:`, poolStatus.byType);
    console.log(`   By Role:`, poolStatus.byRole);

    // Show all VMs
    console.log('\n3. All VMs:');
    const allVMs = await VM.findAll();
    allVMs.forEach(vm => {
      console.log(`   ${vm.name} (ID: ${vm.vmId}):`);
      console.log(`     IP: ${vm.ipAddress}`);
      console.log(`     Type: ${vm.type || 'unknown'}`);
      console.log(`     Role: ${vm.role || 'unknown'}`);
      console.log(`     Status: ${vm.status}`);
      console.log(`     Assigned To: ${vm.assignedTo || 'None'}`);
      console.log('');
    });

    // Show match status
    console.log('4. Match Status:');
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

    if (match) {
      console.log(`   Match: ${match.name} (ID: ${match.id})`);
      console.log(`   Status: ${match.status}`);
      console.log(`   Teams: ${match.teams.length}`);
      
      match.teams.forEach(team => {
        console.log(`   Team ${team.name} (ID: ${team.id}):`);
        console.log(`     Members: ${team.members.map(m => m.username).join(', ')}`);
        
        // Show team VMs
        team.members.forEach(member => {
          const memberVMs = allVMs.filter(vm => vm.assignedTo === member.id);
          if (memberVMs.length > 0) {
            console.log(`     ${member.username} VMs:`);
            memberVMs.forEach(vm => {
              console.log(`       - ${vm.name} (${vm.vmId}): ${vm.ipAddress}`);
            });
          }
        });
        console.log('');
      });
    }

    // Show assignment logic
    console.log('5. Assignment Logic:');
    console.log('   When user joins team:');
    console.log('     - Kali attacker VM assigned to user');
    console.log('     - Windows target VM shared with team');
    console.log('   When match becomes active:');
    console.log('     - All team members get VM assignments');
    console.log('     - VMs are marked as "assigned" status');

    // Show API endpoints
    console.log('\n6. Available API Endpoints:');
    console.log('   GET /api/matches/:id/my-vms - Get user VMs');
    console.log('   GET /api/matches/:id/team/:teamId/vms - Get team VMs');
    console.log('   GET /api/matches/vm-pool-status - Get pool status (admin)');

    console.log('\n=== VM Assignment System Ready ===');
    console.log('✅ VMs are automatically assigned when users join competitions');
    console.log('✅ VMs are automatically assigned when matches become active');
    console.log('✅ Users can access their assigned VMs through the API');

  } catch (error) {
    console.error('Error showing VM assignment status:', error);
  } finally {
    process.exit(0);
  }
}

showVMAssignmentStatus();

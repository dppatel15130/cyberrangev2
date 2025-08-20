const { VM } = require('../models');

async function updateVMTypes() {
  try {
    console.log('=== Updating VM Types and Roles ===\n');

    // Update Target VM (ID: 102)
    const targetVM = await VM.findOne({ where: { vmId: '102' } });
    if (targetVM) {
      await targetVM.update({
        name: 'Target-Server-Win7',
        type: 'windows',
        role: 'target',
        isTarget: true,
        isAttacker: false
      });
      console.log('✅ Updated Target VM (ID: 102) - Windows/Target');
    } else {
      console.log('❌ Target VM 102 not found');
    }

    // Update Attacker VM (ID: 103)
    const attackerVM = await VM.findOne({ where: { vmId: '103' } });
    if (attackerVM) {
      await attackerVM.update({
        name: 'Attacker-Kali',
        type: 'kali',
        role: 'attacker',
        isTarget: false,
        isAttacker: true
      });
      console.log('✅ Updated Attacker VM (ID: 103) - Kali/Attacker');
    } else {
      console.log('❌ Attacker VM 103 not found');
    }

    // Show updated VMs
    console.log('\n=== Updated VMs ===');
    const allVMs = await VM.findAll();
    allVMs.forEach(vm => {
      console.log(`${vm.name} (ID: ${vm.vmId}):`);
      console.log(`  IP: ${vm.ipAddress}`);
      console.log(`  Type: ${vm.type || 'unknown'}`);
      console.log(`  Role: ${vm.role || 'unknown'}`);
      console.log(`  Target: ${vm.isTarget ? 'Yes' : 'No'}`);
      console.log(`  Attacker: ${vm.isAttacker ? 'Yes' : 'No'}`);
      console.log(`  Status: ${vm.status}`);
      console.log('');
    });

    console.log('=== VM Types Update Complete ===');

  } catch (error) {
    console.error('Error updating VM types:', error);
  } finally {
    process.exit(0);
  }
}

updateVMTypes();

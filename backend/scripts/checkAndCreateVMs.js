const { sequelize } = require('../config/db');
const { VM } = require('../models');

async function checkAndCreateVMs() {
  try {
    console.log('=== Checking and Creating VMs ===\n');

    // Test database connection
    console.log('1. Testing database connection...');
    await sequelize.authenticate();
    console.log('✅ Database connected successfully');

    // Sync models to create tables if they don't exist
    console.log('\n2. Syncing database models...');
    await sequelize.sync({ alter: true });
    console.log('✅ Database models synced');

    // Check if VMs exist
    console.log('\n3. Checking existing VMs...');
    const existingVMs = await VM.findAll();
    console.log(`Found ${existingVMs.length} existing VMs`);

    if (existingVMs.length === 0) {
      console.log('\n4. Creating VMs...');
      
      // Create Target VM
      const targetVM = await VM.create({
        userId: 1,
        labId: 1,
        vmId: '102',
        ipAddress: '172.16.26.139',
        name: 'Target-Server-Win7',
        type: 'windows',
        role: 'target',
        isTarget: true,
        isAttacker: false,
        status: 'running',
        guacamoleUrl: 'http://172.16.200.136:8080/guacamole'
      });
      console.log('✅ Created Target VM (ID: 102)');

      // Create Attacker VM
      const attackerVM = await VM.create({
        userId: 1,
        labId: 1,
        vmId: '103',
        ipAddress: '172.16.200.136',
        name: 'Attacker-Kali',
        type: 'kali',
        role: 'attacker',
        isTarget: false,
        isAttacker: true,
        status: 'running'
      });
      console.log('✅ Created Attacker VM (ID: 103)');
    } else {
      console.log('\n4. Existing VMs:');
      existingVMs.forEach(vm => {
        console.log(`   ${vm.name} (ID: ${vm.vmId}): ${vm.ipAddress} - ${vm.type}/${vm.role}`);
      });
    }

    // Show final status
    console.log('\n5. Final VM Status:');
    const allVMs = await VM.findAll();
    allVMs.forEach(vm => {
      console.log(`   ${vm.name} (ID: ${vm.vmId}):`);
      console.log(`     IP: ${vm.ipAddress}`);
      console.log(`     Type: ${vm.type || 'unknown'}`);
      console.log(`     Role: ${vm.role || 'unknown'}`);
      console.log(`     Status: ${vm.status}`);
      console.log('');
    });

    console.log('=== VM Setup Complete ===');

  } catch (error) {
    console.error('Error checking/creating VMs:', error);
  } finally {
    process.exit(0);
  }
}

checkAndCreateVMs();

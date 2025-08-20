const { VM, Match } = require('../models');

async function updateVMConfiguration() {
  try {
    console.log('=== Updating VM Configuration ===\n');

    // Update the target VM to match your actual setup
    const targetVM = await VM.findOne({ where: { vmId: '102' } });
    if (targetVM) {
      await targetVM.update({
        ipAddress: '172.16.26.139', // Updated IP
        name: 'Target-Server-Win7',
        os: 'Windows 7',
        status: 'running',
        description: 'Vulnerable Windows 7 target server with Guacamole access',
        isTarget: true,
        guacamoleUrl: 'http://172.16.26.139:8080/guacamole', // Add Guacamole URL
        vulnerabilities: JSON.stringify([
          'ms17-010',
          'eternalblue',
          'smb_v1',
          'weak_passwords',
          'open_ports'
        ])
      });
      console.log('✅ Updated Target VM (ID: 102, IP: 172.16.26.139)');
    } else {
      console.log('❌ Target VM 102 not found');
    }

    // Update or create the attacker VM
    let attackerVM = await VM.findOne({ where: { vmId: '103' } });
    if (!attackerVM) {
      attackerVM = await VM.create({
        vmId: '103',
        ipAddress: '172.16.200.136',
        name: 'Attacker-Kali',
        os: 'Kali Linux',
        status: 'running',
        description: 'Kali Linux attacker machine',
        isAttacker: true,
        userId: 1,
        labId: 1,
        tools: JSON.stringify([
          'nmap',
          'metasploit',
          'nuclei',
          'nikto',
          'dirb'
        ])
      });
      console.log('✅ Created Attacker VM (ID: 103, IP: 172.16.200.136)');
    } else {
      await attackerVM.update({
        ipAddress: '172.16.200.136',
        name: 'Attacker-Kali',
        status: 'running'
      });
      console.log('✅ Updated Attacker VM (ID: 103, IP: 172.16.200.136)');
    }

    // Update match configuration
    const match = await Match.findByPk(3);
    if (match) {
      const networkConfig = JSON.parse(match.networkConfig || '{}');
      networkConfig.targetVM = targetVM ? targetVM.id : null;
      networkConfig.attackerVMs = [attackerVM.id];
      networkConfig.targetSubnet = '172.16.26.0/24';
      networkConfig.attackerSubnet = '172.16.200.0/24';
      
      await match.update({
        networkConfig: JSON.stringify(networkConfig)
      });
      console.log('✅ Updated match network configuration');
    }

    console.log('\n=== VM Configuration Updated ===');
    console.log('Target VM: 172.16.26.139 (VM ID: 102)');
    console.log('Attacker VM: 172.16.200.136 (VM ID: 103)');
    console.log('Guacamole URL: http://172.16.26.139:8080/guacamole');

  } catch (error) {
    console.error('Error updating VM configuration:', error);
  } finally {
    process.exit(0);
  }
}

updateVMConfiguration();

const axios = require('axios');
const https = require('https');

// Configure HTTPS agent to ignore self-signed certificates (for development)
const httpsAgent = new https.Agent({
  rejectUnauthorized: false
});

// Proxmox API configuration
const proxmoxApi = axios.create({
  baseURL: process.env.PROXMOX_API_URL || 'https://172.16.200.129:8006',
  headers: {
    'Authorization': `PVEAPIToken=${process.env.PROXMOX_API_TOKEN_NAME || 'cyberrange@pve!ansible'}=${process.env.PROXMOX_API_TOKEN_VALUE || '9d14390f-b94b-4012-bef5-699670e81cfa'}`,
  },
  httpsAgent: httpsAgent
});

async function checkAllVMs() {
  const results = [];
  
  // Check VMs from 101 to 109
  for (let vmId = 101; vmId <= 109; vmId++) {
    try {
      const response = await proxmoxApi.get(`/nodes/proxmox/qemu/${vmId}/status/current`);
      results.push({
        vmId,
        status: response.data.status,
        name: response.data.name || `VM-${vmId}`,
        cpus: response.data.cpus,
        maxmem: response.data.maxmem,
        mem: response.data.mem,
        uptime: response.data.uptime || 0
      });
    } catch (error) {
      if (error.response && error.response.status === 501) {
        // VM doesn't exist or is not accessible
        results.push({
          vmId,
          status: 'not_found',
          name: `VM-${vmId}`,
          error: 'VM not found or not accessible'
        });
      } else {
        // Other error
        results.push({
          vmId,
          status: 'error',
          name: `VM-${vmId}`,
          error: error.message
        });
      }
    }
  }
  
  return results;
}

// Run the check
checkAllVMs()
  .then(results => {
    console.log('VM Status Report:');
    console.log('=================');
    results.forEach(vm => {
      console.log(`\nVM ID: ${vm.vmId}`);
      console.log(`Name: ${vm.name}`);
      console.log(`Status: ${vm.status.toUpperCase()}`);
      
      if (vm.status === 'running') {
        console.log(`CPUs: ${vm.cpus}`);
        console.log(`Memory: ${Math.round(vm.mem / (1024 * 1024))} MB / ${Math.round(vm.maxmem / (1024 * 1024))} MB`);
        console.log(`Uptime: ${Math.floor(vm.uptime / 3600)}h ${Math.floor((vm.uptime % 3600) / 60)}m`);
      } else if (vm.error) {
        console.log(`Error: ${vm.error}`);
      }
    });
    
    const runningCount = results.filter(vm => vm.status === 'running').length;
    const stoppedCount = results.filter(vm => vm.status === 'stopped').length;
    const errorCount = results.filter(vm => vm.status === 'error' || vm.status === 'not_found').length;
    
    console.log('\nSummary:');
    console.log('========');
    console.log(`Total VMs: ${results.length}`);
    console.log(`Running: ${runningCount}`);
    console.log(`Stopped: ${stoppedCount}`);
    console.log(`Not Found/Error: ${errorCount}`);
  })
  .catch(error => {
    console.error('Error checking VMs:', error);
  });

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

async function checkProxmox() {
  try {
    // First, check if we can access the API
    console.log('Testing Proxmox API connection...');
    
    // Try to get the list of nodes
    const response = await proxmoxApi.get('/nodes');
    
    if (response.data && response.data.data) {
      console.log('\nAvailable Nodes:');
      console.log('================');
      response.data.data.forEach(node => {
        console.log(`- ${node.node} (Status: ${node.status})`);
      });
      
      // For each node, list VMs
      for (const node of response.data.data) {
        console.log(`\nVMs on node ${node.node}:`);
        console.log('======================');
        
        try {
          const vmsResponse = await proxmoxApi.get(`/nodes/${node.node}/qemu`);
          if (vmsResponse.data && vmsResponse.data.data) {
            vmsResponse.data.data.forEach(vm => {
              console.log(`ID: ${vmid} | Name: ${vm.name || 'N/A'} | Status: ${vm.status || 'unknown'}`);
            });
          } else {
            console.log('No VMs found on this node.');
          }
        } catch (vmError) {
          console.error(`Error fetching VMs from node ${node.node}:`, vmError.message);
        }
      }
    } else {
      console.log('Unexpected API response format:', response.data);
    }
  } catch (error) {
    console.error('Error connecting to Proxmox API:');
    if (error.response) {
      console.log('Status:', error.response.status);
      console.log('Response:', error.response.data);
    } else {
      console.log('Error:', error.message);
    }
  }
}

// Run the check
checkProxmox();

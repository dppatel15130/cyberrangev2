const axios = require('axios');
const https = require('https');

// Configuration
const config = {
  baseURL: process.env.PROXMOX_API_URL || 'https://172.16.200.129:8006',
  tokenId: process.env.PROXMOX_API_TOKEN_NAME || 'cyberrange@pve!ansible',
  tokenValue: process.env.PROXMOX_API_TOKEN_VALUE || '9d14390f-b94b-4012-bef5-699670e81cfa',
  verifySSL: false
};

// Create axios instance with the configuration
const api = axios.create({
  baseURL: config.baseURL,
  headers: {
    'Authorization': `PVEAPIToken=${config.tokenId}=${config.tokenValue}`,
    'Accept': 'application/json'
  },
  httpsAgent: new https.Agent({
    rejectUnauthorized: config.verifySSL
  }),
  timeout: 10000 // 10 seconds timeout
});

async function testConnection() {
  console.log('Testing connection to Proxmox API...');
  console.log(`API URL: ${config.baseURL}`);
  console.log(`Token ID: ${config.tokenId}`);
  console.log('Verifying SSL:', config.verifySSL ? 'Enabled' : 'Disabled');
  
  try {
    // Test API version endpoint
    console.log('\n1. Testing API version endpoint...');
    const versionResponse = await api.get('/version');
    console.log('✓ Successfully connected to Proxmox API');
    console.log('Proxmox Version:', versionResponse.data.data);
    
    // Test authentication with a simple endpoint
    console.log('\n2. Testing authentication...');
    const authResponse = await api.get('/access/users');
    console.log('✓ Authentication successful');
    
    // List all nodes
    console.log('\n3. Fetching nodes...');
    const nodesResponse = await api.get('/nodes');
    const nodes = nodesResponse.data.data;
    
    if (nodes && nodes.length > 0) {
      console.log('✓ Found', nodes.length, 'node(s):');
      for (const node of nodes) {
        console.log(`   - ${node.node} (${node.status})`);
        
        // Try to get VMs for this node
        try {
          const vmsResponse = await api.get(`/nodes/${node.node}/qemu`);
          const vms = vmsResponse.data.data || [];
          console.log(`   VMs (${vms.length}):`);
          
          if (vms.length > 0) {
            vms.forEach(vm => {
              console.log(`     - VM ${vmid}: ${vm.name || 'unnamed'} (${vm.status || 'unknown'})`);
            });
          } else {
            console.log('     No VMs found on this node.');
          }
        } catch (vmError) {
          console.log(`   Error fetching VMs: ${vmError.message}`);
        }
      }
    } else {
      console.log('No nodes found in the cluster.');
    }
    
  } catch (error) {
    console.error('\n❌ Error:', error.message);
    
    if (error.response) {
      console.log('Status:', error.response.status);
      console.log('Response data:', error.response.data);
      
      if (error.response.status === 401) {
        console.log('\nAuthentication failed. Please check your API token.');
      } else if (error.response.status === 501) {
        console.log('\nThe requested endpoint does not exist. This could mean:');
        console.log('1. The Proxmox API URL is incorrect');
        console.log('2. The Proxmox API version is not compatible');
        console.log('3. The endpoint requires different permissions');
      }
    } else if (error.request) {
      console.log('No response received. Possible issues:');
      console.log('- Proxmox server is not reachable');
      console.log('- Network connectivity issues');
      console.log('- Incorrect API URL');
    }
    
    console.log('\nTroubleshooting tips:');
    console.log('1. Verify the Proxmox API URL is correct');
    console.log('2. Check if the API token has sufficient permissions');
    console.log('3. Ensure the Proxmox server is running and accessible');
    console.log('4. Check if you need to accept the self-signed certificate');
  }
}

// Run the test
testConnection();

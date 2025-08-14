const axios = require('axios');
const https = require('https');

// Configuration options to test
const configs = [
  {
    name: 'Direct API with token',
    baseURL: 'https://172.16.200.129:8006/api2/json',
    auth: {
      token: 'PVEAPIToken=cyberrange@pve!ansible=9d14390f-b94b-4012-bef5-699670e81cfa'
    },
    verifySSL: false
  },
  {
    name: 'Direct API with username/password',
    baseURL: 'https://172.16.200.129:8006/api2/json',
    auth: {
      username: 'root',
      password: 'your-proxmox-password'  // Replace with actual password
    },
    verifySSL: false
  },
  {
    name: 'With API version',
    baseURL: 'https://172.16.200.129:8006/api2/json',
    auth: {
      token: 'PVEAPIToken=cyberrange@pve!ansible=9d14390f-b94b-4012-bef5-699670e81cfa'
    },
    verifySSL: false
  },
  {
    name: 'Without API version',
    baseURL: 'https://172.16.200.129:8006',
    auth: {
      token: 'PVEAPIToken=cyberrange@pve!ansible=9d14390f-b94b-4012-bef5-699670e81cfa'
    },
    verifySSL: false
  }
];

async function testConfig(config) {
  console.log(`\n=== Testing: ${config.name} ===`);
  console.log(`URL: ${config.baseURL}`);
  
  const instance = axios.create({
    baseURL: config.baseURL,
    httpsAgent: new https.Agent({
      rejectUnauthorized: config.verifySSL
    }),
    timeout: 5000
  });

  // Set auth headers based on config
  if (config.auth.token) {
    instance.defaults.headers.common['Authorization'] = config.auth.token;
  } else if (config.auth.username) {
    const auth = Buffer.from(`${config.auth.username}:${config.auth.password}`).toString('base64');
    instance.defaults.headers.common['Authorization'] = `Basic ${auth}`;
  }

  try {
    // Test 1: Get API version (should work with any auth)
    console.log('\n1. Testing API version endpoint...');
    const versionRes = await instance.get('/version');
    console.log('✓ API Version:', versionRes.data.data);

    // Test 2: Get access ticket (if using username/password)
    if (config.auth.username) {
      console.log('\n2. Testing authentication...');
      const ticketRes = await instance.post('/access/ticket', {
        username: config.auth.username,
        password: config.auth.password
      });
      console.log('✓ Authentication successful');
      console.log('   CSRF Token:', ticketRes.data.data.CSRFPreventionToken);
    }

    // Test 3: List nodes
    console.log('\n3. Listing nodes...');
    const nodesRes = await instance.get('/nodes');
    console.log('✓ Nodes found:', nodesRes.data.data.map(n => `${n.node} (${n.status})`).join(', '));

    // Test 4: List VMs on first node
    if (nodesRes.data.data.length > 0) {
      const node = nodesRes.data.data[0].node;
      console.log(`\n4. Checking VMs on node ${node}...`);
      const vmsRes = await instance.get(`/nodes/${node}/qemu`);
      
      if (vmsRes.data.data && vmsRes.data.data.length > 0) {
        console.log('✓ Found VMs:');
        for (const vm of vmsRes.data.data) {
          const statusRes = await instance.get(`/nodes/${node}/qemu/${vm.vmid}/status/current`);
          console.log(`   - VM ${vm.vmid}: ${vm.name || 'unnamed'} (${statusRes.data.data.status || 'unknown'})`);
        }
      } else {
        console.log('   No VMs found on this node.');
      }
    }

    return { success: true, message: 'All tests passed' };
  } catch (error) {
    let errorDetails = {
      message: error.message,
      config: {
        url: error.config?.url,
        method: error.config?.method,
        headers: error.config?.headers ? Object.keys(error.config.headers) : []
      }
    };

    if (error.response) {
      errorDetails.status = error.response.status;
      errorDetails.statusText = error.response.statusText;
      errorDetails.data = error.response.data;
    }

    return { success: false, error: errorDetails };
  }
}

async function runTests() {
  console.log('Starting Proxmox API connection tests...');
  console.log('======================================');

  for (const config of configs) {
    const result = await testConfig(config);
    
    if (result.success) {
      console.log(`\n✅ ${config.name}: Success!\n`);
    } else {
      console.log(`\n❌ ${config.name}: Failed`);
      console.log('Error:', result.error.message);
      
      if (result.error.status) {
        console.log(`Status: ${result.error.status} ${result.error.statusText}`);
      }
      
      if (result.error.data) {
        console.log('Response:', JSON.stringify(result.error.data, null, 2));
      }
      
      console.log('\nTroubleshooting:');
      if (result.error.status === 401) {
        console.log('- Check your authentication credentials');
        console.log('- Verify the token has sufficient permissions');
      } else if (result.error.status === 501) {
        console.log('- The API endpoint may be incorrect');
        console.log('- Check if the Proxmox version supports this endpoint');
      } else if (result.error.code === 'ECONNREFUSED') {
        console.log('- Proxmox server is not reachable at the specified URL');
        console.log('- Check if the server is running and accessible');
        console.log('- Verify the port number is correct');
      } else if (result.error.code === 'UNABLE_TO_VERIFY_LEAF_SIGNATURE') {
        console.log('- SSL certificate verification failed');
        console.log('- You may need to set verifySSL: true and provide the CA certificate');
      }
      
      console.log(''); // Add empty line
    }
  }
}

// Run the tests
runTests().catch(console.error);

const axios = require('axios');

// Configuration
const API_BASE_URL = 'http://localhost:5000/api';
const TEST_CREDENTIALS = {
  username: 'admin',  // Default admin username
  password: 'admin123'   // Default admin password
};

async function testVmStatus() {
  try {
    console.log('Testing VM Status Endpoint');
    console.log('=========================');

    // Step 1: Login to get JWT token
    console.log('\n1. Logging in...');
    const loginResponse = await axios.post(`${API_BASE_URL}/auth/login`, TEST_CREDENTIALS);
    
    if (!loginResponse.data.token) {
      throw new Error('Login failed - no token received');
    }
    
    const token = loginResponse.data.token;
    console.log('✓ Login successful');
    console.log(`   Token: ${token.substring(0, 20)}...`);

    // Set up headers with the received token
    const config = {
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      }
    };

    // Step 2: Test VM status endpoint for VM 101
    console.log('\n2. Testing VM status for VM 101...');
    const vmId = 101;
    const statusResponse = await axios.get(`${API_BASE_URL}/vms/${vmId}`, config);
    
    console.log('✓ VM Status Response:');
    console.log(JSON.stringify(statusResponse.data, null, 2));

    // Step 3: Test getting all VMs (admin only)
    console.log('\n3. Testing get all VMs (admin only)...');
    const allVmsResponse = await axios.get(`${API_BASE_URL}/vms`, config);
    
    console.log('✓ All VMs Response:');
    console.log(JSON.stringify(allVmsResponse.data, null, 2));

  } catch (error) {
    console.error('\n❌ Test failed:');
    
    if (error.response) {
      // The request was made and the server responded with a status code
      // that falls out of the range of 2xx
      console.error('Status:', error.response.status);
      console.error('Data:', error.response.data);
      console.error('Headers:', error.response.headers);
    } else if (error.request) {
      // The request was made but no response was received
      console.error('No response received:', error.request);
    } else {
      // Something happened in setting up the request that triggered an Error
      console.error('Error:', error.message);
    }
    
    console.error('\nTroubleshooting tips:');
    console.log('- Make sure the backend server is running');
    console.log('- Check if the database is accessible');
    console.log('- Verify the Proxmox server is reachable');
    console.log('- Check server logs for any errors');
  }
}

// Run the test
testVmStatus();

const axios = require('axios');

async function createGuacamoleUser() {
  try {
    console.log('=== Manual Guacamole User Creation Test ===\n');
    
    const baseUrl = 'http://172.16.200.136:8080/guacamole';
    const username = 'admin';
    const password = 'sac@1234';
    
    console.log('Step 1: Testing basic connectivity...');
    try {
      const response = await axios.get(baseUrl, { timeout: 5000 });
      console.log('✅ Guacamole main page accessible');
    } catch (error) {
      console.log('❌ Guacamole not accessible:', error.message);
      return;
    }
    
    console.log('\nStep 2: Testing authentication...');
    try {
      const authResponse = await axios.post(`${baseUrl}/api/tokens`, {
        username: 'guacadmin',
        password: 'guacadmin'
      }, {
        headers: { 'Content-Type': 'application/json' },
        timeout: 5000
      });
      
      console.log('✅ Authentication successful');
      console.log('Auth token received');
      
      const authToken = authResponse.data.authToken;
      
      console.log('\nStep 3: Creating test user...');
      const userData = {
        username: username,
        password: password,
        attributes: {
          fullName: username,
          emailAddress: `${username}@cyberrange.com`,
          organization: 'CyberRange',
          role: 'USER'
        }
      };
      
      const createResponse = await axios.post(`${baseUrl}/api/session/data/mysql/users`, userData, {
        headers: {
          'Authorization': `Bearer ${authToken}`,
          'Content-Type': 'application/json'
        },
        timeout: 5000
      });
      
      console.log('✅ User created successfully');
      console.log('User ID:', createResponse.data.identifier);
      
      console.log('\nStep 4: Getting connections...');
      const connectionsResponse = await axios.get(`${baseUrl}/api/session/data/mysql/connections`, {
        headers: {
          'Authorization': `Bearer ${authToken}`
        },
        timeout: 5000
      });
      
      console.log('✅ Connections retrieved');
      console.log('Available connections:', connectionsResponse.data.map(c => c.name));
      
      console.log('\n=== Test Complete ===');
      console.log(`User ${username} created with password ${password}`);
      console.log(`Login URL: ${baseUrl}`);
      
    } catch (authError) {
      console.log('❌ Authentication failed:', authError.message);
      if (authError.response) {
        console.log('Response status:', authError.response.status);
        console.log('Response data:', authError.response.data);
      }
    }
    
  } catch (error) {
    console.error('Test error:', error);
  } finally {
    process.exit(0);
  }
}

createGuacamoleUser();

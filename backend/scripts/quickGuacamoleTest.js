const axios = require('axios');

async function quickGuacamoleTest() {
  try {
    console.log('=== Quick Guacamole Test ===\n');
    
    const baseUrl = 'http://172.16.200.136:8080/guacamole';
    
    console.log('Testing connection to:', baseUrl);
    
    try {
      const response = await axios.get(baseUrl, { timeout: 5000 });
      console.log('✅ Guacamole is accessible');
      console.log('Status:', response.status);
      console.log('Response length:', response.data.length);
    } catch (error) {
      console.log('❌ Guacamole is not accessible');
      console.log('Error:', error.message);
      
      if (error.code === 'ECONNREFUSED') {
        console.log('Suggestion: Guacamole service might not be running');
      } else if (error.code === 'ENOTFOUND') {
        console.log('Suggestion: Check if the IP address is correct');
      }
    }
    
    console.log('\n=== Test Complete ===');
    
  } catch (error) {
    console.error('Test error:', error);
  } finally {
    process.exit(0);
  }
}

quickGuacamoleTest();

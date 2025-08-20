const guacamoleService = require('../services/guacamoleService');
const { User, Team } = require('../models');

async function testGuacamoleIntegration() {
  try {
    console.log('=== Testing Guacamole Integration ===\n');

    // Test 1: Check Guacamole connectivity
    console.log('1. Testing Guacamole connectivity...');
    const connectionTest = await guacamoleService.testConnection();
    if (connectionTest.success) {
      console.log('✅ Guacamole is accessible');
    } else {
      console.log('❌ Guacamole is not accessible:', connectionTest.error);
      console.log('Please ensure Guacamole is running at http://172.16.26.139:8080/guacamole');
      return;
    }

    // Test 2: Authenticate with Guacamole
    console.log('\n2. Testing Guacamole authentication...');
    const authTest = await guacamoleService.authenticate();
    if (authTest) {
      console.log('✅ Guacamole authentication successful');
    } else {
      console.log('❌ Guacamole authentication failed');
      console.log('Please check guacadmin/guacadmin credentials');
      return;
    }

    // Test 3: Setup access for admin user
    console.log('\n3. Testing user creation for admin...');
    const adminUser = await User.findOne({ where: { email: 'admin@gmail.com' } });
    if (adminUser) {
      const userSetup = await guacamoleService.setupUserAccess(adminUser);
      if (userSetup.success) {
        console.log('✅ Admin user Guacamole access configured');
        console.log('Credentials:', userSetup.credentials);
      } else {
        console.log('❌ Failed to setup admin user access:', userSetup.error);
      }
    } else {
      console.log('❌ Admin user not found');
    }

    // Test 4: Setup access for teams
    console.log('\n4. Testing team access setup...');
    const teams = await Team.findAll({
      include: [{ model: User, as: 'members' }]
    });

    for (const team of teams) {
      console.log(`\nSetting up access for team: ${team.name}`);
      const teamSetup = await guacamoleService.setupTeamAccess(team.id);
      
      if (teamSetup.success) {
        console.log(`✅ Team ${team.name} access configured`);
        teamSetup.results.forEach(result => {
          console.log(`  - ${result.username}: ${result.success ? '✅' : '❌'} ${result.message}`);
        });
      } else {
        console.log(`❌ Failed to setup team ${team.name} access:`, teamSetup.error);
      }
    }

    // Test 5: Show connection information
    console.log('\n5. Connection Information:');
    console.log('Guacamole URL: http://172.16.26.139:8080/guacamole');
    console.log('Default password for all users: sac@1234');
    console.log('\nUsers can now:');
    console.log('1. Go to Guacamole URL');
    console.log('2. Login with their CyberRange username and password "sac@1234"');
    console.log('3. Access the Windows7-Target connection');
    console.log('4. Login to Windows 7 with admin/password123');

    console.log('\n=== Guacamole Integration Test Complete ===');

  } catch (error) {
    console.error('Error testing Guacamole integration:', error);
  } finally {
    process.exit(0);
  }
}

testGuacamoleIntegration();

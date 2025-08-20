const { VM, Match } = require('../models');

async function setupGuacamoleIntegration() {
  try {
    console.log('=== Setting up Guacamole Integration ===\n');

    // Update the target VM with Guacamole configuration
    const targetVM = await VM.findOne({ where: { vmId: '102' } });
    if (targetVM) {
      await targetVM.update({
        guacamoleUrl: 'http://172.16.200.136:8080/guacamole',
        guacamoleConfig: JSON.stringify({
          hostname: '172.16.26.139',
          port: 3389,
          protocol: 'rdp',
          username: 'admin',
          password: 'password123',
          domain: '',
          security: 'any',
          ignoreCert: true,
          enableWallpaper: false,
          enableTheming: false,
          enableFontSmoothing: true,
          enableFullWindowDrag: false,
          enableDesktopComposition: false,
          enableMenuAnimations: false,
          disableBitmapCaching: false,
          disableOffscreenCaching: false,
          disableGlyphCaching: false,
          preconnectionId: '',
          preconnectionBlob: '',
          gatewayHostname: '',
          gatewayPort: 4822,
          gatewayUsername: '',
          gatewayPassword: '',
          gatewayDomain: '',
          loadBalanceInfo: '',
          recordingPath: '',
          recordingName: '',
          recordingExcludeOutput: false,
          recordingExcludeMouse: false,
          recordingIncludeKeys: false,
          createRecordingPath: false,
          enableSFTP: false,
          sftpHostname: '',
          sftpPort: 22,
          sftpUsername: '',
          sftpPassword: '',
          sftpPrivateKey: '',
          sftpPassphrase: '',
          sftpDirectory: '',
          sftpServerAliveInterval: 0,
          sftpServerAliveCountMax: 0,
          enableAudioInput: false,
          enableAudioOutput: false,
          enablePrinting: false,
          enableDrive: false,
          enableWallpaper: false,
          createDrivePath: false,
          enableFullWindowDrag: false,
          enableDesktopComposition: false,
          enableMenuAnimations: false,
          enableTheming: false,
          enableFontSmoothing: true,
          enableCursorBlinking: false,
          enableCursorShadow: false,
          enableBold: false,
          colorDepth: 16
        })
      });
      console.log('✅ Updated Target VM with Guacamole configuration');
    }

    // Create a Guacamole service integration
    const guacamoleService = {
      baseUrl: 'http://172.16.200.136:8080/guacamole',
      apiEndpoint: 'http://172.16.200.136:8080/guacamole/api',
      credentials: {
        username: 'guacadmin',
        password: 'guacadmin' // Default Guacamole admin password
      },
      connections: {
        targetVM: {
          name: 'Windows7-Target',
          protocol: 'rdp',
          hostname: '172.16.26.139',
          port: 3389,
          username: 'admin',
          password: 'password123'
        }
      }
    };

    // Update match with Guacamole integration
    const match = await Match.findByPk(3);
    if (match) {
      const matchConfig = JSON.parse(match.matchConfig || '{}');
      matchConfig.guacamoleIntegration = guacamoleService;
      
      await match.update({
        matchConfig: JSON.stringify(matchConfig)
      });
      console.log('✅ Updated match with Guacamole integration');
    }

    console.log('\n=== Guacamole Integration Complete ===');
    console.log('Guacamole URL: http://172.16.200.136:8080/guacamole');
    console.log('Default credentials: guacadmin/guacadmin');
    console.log('Target VM connection: Windows7-Target (RDP)');
    console.log('Target VM credentials: admin/password123');

    // Create a simple test script for Guacamole connection
    console.log('\n=== Testing Guacamole Connection ===');
    console.log('You can test the connection by:');
    console.log('1. Opening: http://172.16.200.136:8080/guacamole');
    console.log('2. Login with: guacadmin/guacadmin');
    console.log('3. Click on "Windows7-Target" connection');
    console.log('4. Login with: admin/password123');

  } catch (error) {
    console.error('Error setting up Guacamole integration:', error);
  } finally {
    process.exit(0);
  }
}

setupGuacamoleIntegration();

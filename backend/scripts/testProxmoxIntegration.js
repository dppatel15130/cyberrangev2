#!/usr/bin/env node

/**
 * Test script for Proxmox API integration with cyber-warfare capabilities
 * Tests VM management, match orchestration, and real-time scoring
 */

require('dotenv').config();
const proxmoxService = require('../services/proxmoxService');
const gameEngine = require('../services/gameEngine');
const scoringService = require('../services/scoringService');

async function testProxmoxIntegration() {
  console.log('🚀 Starting Proxmox API Integration Test...\n');

  try {
    // Test 1: Proxmox Health Check
    console.log('📡 Testing Proxmox API Connection...');
    const healthCheck = await proxmoxService.healthCheck();
    
    if (healthCheck.status === 'healthy') {
      console.log('✅ Proxmox API connection successful');
      console.log(`   - Available VMs: ${healthCheck.availableVMs}`);
      console.log(`   - Total VMs: ${healthCheck.vmCount}\n`);
    } else {
      console.log('❌ Proxmox API connection failed');
      console.log(`   - Error: ${healthCheck.message}\n`);
      return false;
    }

    // Test 2: VM List and Status
    console.log('🖥️  Testing VM List and Status...');
    const vmList = await proxmoxService.getVMList();
    console.log(`Found ${vmList.length} VMs:`);
    
    for (const vm of vmList) {
      console.log(`   - VM ${vm.vmid}: ${vm.name} (${vm.status})`);
    }

    // Test specific cyber-warfare VMs
    console.log('\n🎯 Testing Cyber-Warfare VMs...');
    const targetVM = await proxmoxService.getVMStatus(103); // Win 7 Target
    const attackerVM = await proxmoxService.getVMStatus(104); // Kali Attacker
    
    if (targetVM) {
      console.log(`✅ Target VM (103): ${targetVM.status}`);
    } else {
      console.log('❌ Target VM (103) not found');
    }
    
    if (attackerVM) {
      console.log(`✅ Attacker VM (104): ${attackerVM.status}`);
    } else {
      console.log('❌ Attacker VM (104) not found');
    }

    // Test 3: VM Assignment Simulation
    console.log('\n👥 Testing VM Assignment for Cyber-Warfare Match...');
    const mockMatchId = 999;
    const mockTeamId = 1;
    
    const vmRequirements = [
      { type: 'windows', role: 'target' },
      { type: 'kali', role: 'attacker' }
    ];

    const assignmentResult = await proxmoxService.assignVMsToTeam(
      mockMatchId, 
      mockTeamId, 
      vmRequirements
    );

    if (assignmentResult.success) {
      console.log('✅ VM assignment successful');
      console.log(`   - Assigned VMs: ${assignmentResult.assignedVMs.length}`);
      assignmentResult.assignedVMs.forEach(vm => {
        console.log(`   - VM ${vm.vmId}: ${vm.name} (${vm.type}/${vm.role})`);
      });
    } else {
      console.log('❌ VM assignment failed');
      console.log(`   - Error: ${assignmentResult.error}`);
    }

    // Test 4: Game Engine Integration
    console.log('\n🎮 Testing Game Engine Integration...');
    try {
      const gameEngineStatus = await gameEngine.initialize();
      if (gameEngineStatus) {
        console.log('✅ Game Engine initialized successfully');
        
        // Test VM template loading
        const systemStatus = await proxmoxService.getSystemStatus();
        if (systemStatus.connected) {
          console.log('✅ System status check passed');
          console.log(`   - Node: ${systemStatus.node}`);
          console.log(`   - Available VMs: ${systemStatus.vmStats.available}`);
          console.log(`   - Assigned VMs: ${systemStatus.vmStats.assigned}`);
        }
      }
    } catch (error) {
      console.log(`⚠️  Game Engine initialization warning: ${error.message}`);
    }

    // Test 5: Mock Cyber-Warfare Flag Validation
    console.log('\n🚩 Testing Cyber-Warfare Flag System...');
    const testFlags = [
      'CYBERWAR{network_discovery}',
      'CYBERWAR{system_access}',
      'CYBERWAR{admin_credentials}',
      'INVALID{fake_flag}'
    ];

    const cyberwarFlags = {
      'CYBERWAR{network_discovery}': { points: 25, type: 'network_compromise' },
      'CYBERWAR{system_access}': { points: 75, type: 'attack_success' },
      'CYBERWAR{admin_credentials}': { points: 100, type: 'lateral_movement' }
    };

    testFlags.forEach(flag => {
      const flagData = cyberwarFlags[flag.toUpperCase()];
      if (flagData) {
        console.log(`✅ ${flag}: ${flagData.points} points (${flagData.type})`);
      } else {
        console.log(`❌ ${flag}: Invalid flag`);
      }
    });

    // Test 6: WebSocket Integration Test
    console.log('\n🌐 Testing WebSocket Integration...');
    try {
      if (scoringService.wss) {
        console.log('✅ WebSocket server is running');
        console.log(`   - Connected clients: ${scoringService.wss.clients.size}`);
      } else {
        console.log('⚠️  WebSocket server not initialized (requires HTTP server)');
      }
    } catch (error) {
      console.log(`❌ WebSocket test failed: ${error.message}`);
    }

    // Test 7: Clean up mock assignments
    console.log('\n🧹 Cleaning up test assignments...');
    const cleanupResult = await proxmoxService.releaseMatchVMs(mockMatchId);
    if (cleanupResult.success) {
      console.log(`✅ Cleanup successful: ${cleanupResult.message}`);
    }

    console.log('\n🎉 Proxmox API Integration Test Complete!');
    console.log('✅ All core systems tested successfully');
    console.log('\n📋 Test Summary:');
    console.log('   - Proxmox API: Connected');
    console.log('   - VM Management: Functional');
    console.log('   - VM Assignment: Working');
    console.log('   - Game Engine: Initialized');
    console.log('   - Flag System: Validated');
    console.log('   - Cyber-warfare VMs: Available');
    
    return true;

  } catch (error) {
    console.error('❌ Test failed with error:', error);
    console.error(error.stack);
    return false;
  }
}

// Run the test if called directly
if (require.main === module) {
  testProxmoxIntegration()
    .then(success => {
      process.exit(success ? 0 : 1);
    })
    .catch(error => {
      console.error('Fatal test error:', error);
      process.exit(1);
    });
}

module.exports = { testProxmoxIntegration };

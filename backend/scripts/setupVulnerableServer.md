# 🎯 Vulnerable Windows 7 Server Setup Guide

## **Target Server Configuration**
- **IP Address**: 172.16.26.132
- **OS**: Windows 7 Professional/Enterprise
- **Purpose**: Target for vulnerability exploitation

## **Step 1: Install Windows 7**

1. **Download Windows 7 ISO** (if not already installed)
2. **Install with these settings**:
   - Username: `admin`
   - Password: `password123` (weak password for testing)
   - Disable Windows Update (to prevent patches)
   - Disable Windows Firewall (or configure to allow specific ports)

## **Step 2: Enable Vulnerable Services**

### **Enable SMB Version 1 (MS17-010)**
```cmd
# Run as Administrator
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v SMB1 /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v SMB2 /t REG_DWORD /d 0 /f
```

### **Enable RDP (Remote Desktop)**
```cmd
# Enable RDP
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f

# Allow RDP through firewall
netsh advfirewall firewall set rule group="remote desktop" new enable=Yes
```

### **Enable Telnet (Optional)**
```cmd
# Enable Telnet server
dism /online /Enable-Feature /FeatureName:TelnetServer
```

## **Step 3: Configure Network Services**

### **Open Required Ports**
```cmd
# Open ports for services
netsh advfirewall firewall add rule name="SMB" dir=in action=allow protocol=TCP localport=445
netsh advfirewall firewall add rule name="RDP" dir=in action=allow protocol=TCP localport=3389
netsh advfirewall firewall add rule name="HTTP" dir=in action=allow protocol=TCP localport=80
netsh advfirewall firewall add rule name="FTP" dir=in action=allow protocol=TCP localport=21
netsh advfirewall firewall add rule name="SSH" dir=in action=allow protocol=TCP localport=22
```

### **Install IIS (Web Server)**
```cmd
# Install IIS
dism /online /Enable-Feature /FeatureName:IIS-WebServerRole
dism /online /Enable-Feature /FeatureName:IIS-WebServer
dism /online /Enable-Feature /FeatureName:IIS-CommonHttpFeatures
dism /online /Enable-Feature /FeatureName:IIS-HttpErrors
dism /online /Enable-Feature /FeatureName:IIS-HttpLogging
dism /online /Enable-Feature /FeatureName:IIS-RequestFiltering
dism /online /Enable-Feature /FeatureName:IIS-StaticContent
```

## **Step 4: Create Vulnerable Web Application**

### **Create a simple vulnerable web app**
Create file: `C:\inetpub\wwwroot\vulnerable.php`
```php
<?php
// Vulnerable web application
if(isset($_GET['cmd'])) {
    $cmd = $_GET['cmd'];
    system($cmd); // Command injection vulnerability
}

if(isset($_POST['file'])) {
    $file = $_POST['file'];
    include($file); // File inclusion vulnerability
}
?>

<!DOCTYPE html>
<html>
<head><title>Vulnerable Server</title></head>
<body>
    <h1>Welcome to Vulnerable Server</h1>
    <p>This server has multiple vulnerabilities for testing:</p>
    <ul>
        <li>MS17-010 (EternalBlue)</li>
        <li>Weak passwords</li>
        <li>Command injection</li>
        <li>File inclusion</li>
        <li>Open ports</li>
    </ul>
    
    <form method="GET">
        <input type="text" name="cmd" placeholder="Enter command">
        <input type="submit" value="Execute">
    </form>
</body>
</html>
```

## **Step 5: Install Vulnerable Software**

### **Install XAMPP (includes vulnerable services)**
1. Download XAMPP for Windows
2. Install with default settings
3. Start Apache and MySQL services
4. Create weak database passwords

### **Install FTP Server**
```cmd
# Install FTP server
dism /online /Enable-Feature /FeatureName:IIS-FTPServer
dism /online /Enable-Feature /FeatureName:IIS-FTPSvc
```

## **Step 6: Create Test Accounts**

### **Create weak user accounts**
```cmd
# Create admin account with weak password
net user admin password123 /add
net localgroup administrators admin /add

# Create regular user
net user user1 password123 /add

# Create guest account
net user guest password123 /add
net user guest /active:yes
```

## **Step 7: Disable Security Features**

### **Disable Windows Defender**
```cmd
# Disable Windows Defender (for testing only!)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableBehaviorMonitoring /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableOnAccessProtection /t REG_DWORD /d 1 /f
```

### **Disable UAC**
```cmd
# Disable User Account Control
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 0 /f
```

## **Step 8: Create Flag Files**

### **Create flag files for teams to find**
```cmd
# Create flag directories
mkdir C:\flags
mkdir C:\flags\web
mkdir C:\flags\system
mkdir C:\flags\hidden

# Create flag files
echo CYBERWAR{eternalblue_ms17_010} > C:\flags\system\ms17-010.txt
echo CYBERWAR{smb_v1_enabled} > C:\flags\system\smb-v1.txt
echo CYBERWAR{ports_21_22_80_445_3389} > C:\flags\system\open-ports.txt
echo CYBERWAR{admin_password123} > C:\flags\system\weak-password.txt
echo CYBERWAR{rdp_access_gained} > C:\flags\system\rdp-access.txt

# Create web flags
echo CYBERWAR{web_vulnerability_found} > C:\inetpub\wwwroot\flag.txt
echo CYBERWAR{command_injection_success} > C:\inetpub\wwwroot\admin\flag.txt
```

## **Step 9: Network Configuration**

### **Set Static IP**
```cmd
# Configure network adapter
netsh interface ip set address "Local Area Connection" static 172.16.26.132 255.255.255.0 172.16.26.1
netsh interface ip set dns "Local Area Connection" static 8.8.8.8
```

### **Test Connectivity**
```cmd
# Test network connectivity
ping 172.16.200.136
ping 8.8.8.8
```

## **Step 10: Verification Script**

### **Create verification script**
Create file: `C:\verify_vulnerabilities.bat`
```batch
@echo off
echo === Vulnerability Verification ===

echo.
echo 1. Checking SMB version...
reg query "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v SMB1

echo.
echo 2. Checking open ports...
netstat -an | findstr ":445"
netstat -an | findstr ":3389"
netstat -an | findstr ":80"

echo.
echo 3. Checking user accounts...
net user

echo.
echo 4. Checking services...
sc query | findstr "Running"

echo.
echo 5. Checking flag files...
dir C:\flags /s

echo.
echo === Verification Complete ===
pause
```

## **Step 11: Security Warnings**

⚠️ **IMPORTANT SECURITY NOTES:**
- This server is intentionally vulnerable for educational purposes
- **NEVER** expose this server to the internet
- Use only in isolated lab environment
- Disable all security features only for testing
- Reset to secure configuration after testing

## **Step 12: Testing Vulnerabilities**

### **From Kali Linux (172.16.200.136), test:**

1. **MS17-010 Scan**:
```bash
nmap -p 445 --script smb-vuln-ms17-010 172.16.26.132
```

2. **SMB Enumeration**:
```bash
nmap -p 445 --script smb-protocols 172.16.26.132
```

3. **Port Scan**:
```bash
nmap -sS -p- 172.16.26.132
```

4. **Brute Force Test**:
```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt 172.16.26.132 smb
```

5. **RDP Test**:
```bash
xfreerdp /v:172.16.26.132 /u:admin /p:password123
```

## **Step 13: Automated Setup Script**

### **Create automated setup script**
Create file: `setup_vulnerable_server.ps1`
```powershell
# PowerShell script to automate setup
Write-Host "Setting up Vulnerable Windows 7 Server..." -ForegroundColor Green

# Enable SMBv1
Write-Host "Enabling SMBv1..." -ForegroundColor Yellow
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v SMB1 /t REG_DWORD /d 1 /f

# Enable RDP
Write-Host "Enabling RDP..." -ForegroundColor Yellow
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f

# Open firewall ports
Write-Host "Opening firewall ports..." -ForegroundColor Yellow
netsh advfirewall firewall add rule name="SMB" dir=in action=allow protocol=TCP localport=445
netsh advfirewall firewall add rule name="RDP" dir=in action=allow protocol=TCP localport=3389
netsh advfirewall firewall add rule name="HTTP" dir=in action=allow protocol=TCP localport=80

# Create test accounts
Write-Host "Creating test accounts..." -ForegroundColor Yellow
net user admin password123 /add
net localgroup administrators admin /add

# Create flag files
Write-Host "Creating flag files..." -ForegroundColor Yellow
mkdir C:\flags
echo CYBERWAR{eternalblue_ms17_010} > C:\flags\ms17-010.txt
echo CYBERWAR{smb_v1_enabled} > C:\flags\smb-v1.txt

Write-Host "Setup complete!" -ForegroundColor Green
```

## **Step 14: Monitoring and Logging**

### **Enable logging for monitoring**
```cmd
# Enable audit logging
auditpol /set /category:* /success:enable /failure:enable

# Enable SMB logging
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v EnableSecuritySignature /t REG_DWORD /d 0 /f
```

## **Step 15: Integration with ELK Stack**

### **Configure Windows Event Forwarding to ELK**
1. Install Winlogbeat on Windows 7
2. Configure to send logs to Elasticsearch (172.16.200.136:9200)
3. Monitor security events in Kibana

---

## **🎯 Ready for Cyber Warfare Match!**

Once this setup is complete, your Windows 7 server will be vulnerable to:
- ✅ MS17-010 EternalBlue exploitation
- ✅ SMB version 1 attacks
- ✅ Weak password brute forcing
- ✅ RDP access
- ✅ Web application vulnerabilities
- ✅ Port scanning and enumeration

The automated scoring system will detect when teams successfully exploit these vulnerabilities and award points accordingly!

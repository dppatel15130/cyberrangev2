#!/bin/bash

echo "=== Fixing Filebeat Configuration ==="

# Stop filebeat service
echo "1. Stopping Filebeat service..."
sudo systemctl stop filebeat

# Check if filebeat is installed
if ! command -v filebeat &> /dev/null; then
    echo "Filebeat not found. Installing..."
    wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
    echo "deb https://artifacts.elastic.co/packages/7.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-7.x.list
    sudo apt update
    sudo apt install filebeat -y
fi

# Backup original config
echo "2. Backing up original configuration..."
sudo cp /etc/filebeat/filebeat.yml /etc/filebeat/filebeat.yml.backup

# Create new configuration
echo "3. Creating new Filebeat configuration..."
sudo tee /etc/filebeat/filebeat.yml > /dev/null << 'EOF'
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /var/log/auth.log
    - /var/log/syslog
    - /var/log/kern.log
  fields:
    source: kali-linux
    environment: cyberwar

- type: log
  enabled: true
  paths:
    - /home/kali/.msf4/logs/*.log
  fields:
    source: metasploit
    environment: cyberwar

processors:
- add_host_metadata:
    when.not.contains.tags: forwarded
- add_cloud_metadata: ~

output.elasticsearch:
  hosts: ["172.16.200.136:9200"]
  index: "kali-logs-%{+yyyy.MM.dd}"
  username: "elastic"
  password: "changeme"

setup.kibana:
  host: "172.16.200.136:5601"

logging.level: info
logging.to_files: true
logging.files:
  path: /var/log/filebeat
  name: filebeat
  keepfiles: 7
  permissions: 0644
EOF

# Set proper permissions
echo "4. Setting proper permissions..."
sudo chown root:root /etc/filebeat/filebeat.yml
sudo chmod 644 /etc/filebeat/filebeat.yml

# Create log directory
echo "5. Creating log directory..."
sudo mkdir -p /var/log/filebeat
sudo chown root:root /var/log/filebeat

# Test configuration
echo "6. Testing Filebeat configuration..."
sudo filebeat test config -c /etc/filebeat/filebeat.yml

if [ $? -eq 0 ]; then
    echo "✅ Configuration test passed!"
else
    echo "❌ Configuration test failed. Creating minimal config..."
    sudo tee /etc/filebeat/filebeat.yml > /dev/null << 'EOF'
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /var/log/auth.log

output.elasticsearch:
  hosts: ["172.16.200.136:9200"]
  index: "kali-logs-%{+yyyy.MM.dd}"

logging.level: info
EOF
fi

# Test connection to Elasticsearch
echo "7. Testing Elasticsearch connection..."
if curl -s "172.16.200.136:9200" > /dev/null; then
    echo "✅ Elasticsearch is reachable"
else
    echo "⚠️  Elasticsearch not reachable. Using console output instead..."
    sudo tee /etc/filebeat/filebeat.yml > /dev/null << 'EOF'
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /var/log/auth.log

output.console:
  pretty: true

logging.level: info
EOF
fi

# Start filebeat
echo "8. Starting Filebeat service..."
sudo systemctl daemon-reload
sudo systemctl enable filebeat
sudo systemctl start filebeat

# Check status
echo "9. Checking Filebeat status..."
sleep 3
sudo systemctl status filebeat --no-pager -l

# Show logs if there are issues
if ! sudo systemctl is-active --quiet filebeat; then
    echo "❌ Filebeat failed to start. Checking logs..."
    sudo journalctl -u filebeat --no-pager -l --since "5 minutes ago"
    
    echo "🔧 Trying alternative configuration..."
    sudo tee /etc/filebeat/filebeat.yml > /dev/null << 'EOF'
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /var/log/auth.log

output.console:
  pretty: true

logging.level: debug
EOF
    
    sudo systemctl restart filebeat
    sleep 2
    sudo systemctl status filebeat --no-pager -l
fi

echo "=== Filebeat Fix Complete ==="
echo "If Filebeat is still not working, you can run it manually for testing:"
echo "sudo filebeat -e -c /etc/filebeat/filebeat.yml"

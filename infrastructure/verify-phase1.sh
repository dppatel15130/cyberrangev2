#!/bin/bash
# Verification Script for CyberRange Phase 1 Infrastructure
# Run this script to verify deployment status

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Verification functions
check_service() {
    local service=$1
    local host=$2
    local port=$3
    local timeout=${4:-10}
    
    if timeout $timeout bash -c "echo >/dev/tcp/$host/$port" 2>/dev/null; then
        echo -e "${GREEN}✓${NC} $service ($host:$port) is running"
        return 0
    else
        echo -e "${RED}✗${NC} $service ($host:$port) is not accessible"
        return 1
    fi
}

check_docker_service() {
    local container=$1
    
    if docker ps | grep -q "$container.*Up"; then
        echo -e "${GREEN}✓${NC} Docker container '$container' is running"
        return 0
    else
        echo -e "${RED}✗${NC} Docker container '$container' is not running"
        return 1
    fi
}

check_network_interface() {
    local interface=$1
    
    if ip link show "$interface" >/dev/null 2>&1; then
        local status=$(ip link show "$interface" | grep -o 'state [A-Z]*' | cut -d' ' -f2)
        if [ "$status" = "UP" ]; then
            echo -e "${GREEN}✓${NC} Network interface '$interface' is up"
            return 0
        else
            echo -e "${YELLOW}⚠${NC} Network interface '$interface' exists but is down"
            return 1
        fi
    else
        echo -e "${RED}✗${NC} Network interface '$interface' not found"
        return 1
    fi
}

main() {
    echo -e "${BLUE}CyberRange Phase 1 Infrastructure Verification${NC}"
    echo -e "${BLUE}================================================${NC}"
    echo ""
    
    local passed=0
    local total=0
    
    echo -e "${YELLOW}Checking Network Infrastructure:${NC}"
    ((total++)); check_network_interface "vmbr0" && ((passed++)) || true
    ((total++)); check_network_interface "tap-mirror" && ((passed++)) || true
    echo ""
    
    echo -e "${YELLOW}Checking Docker Services:${NC}"
    ((total++)); check_docker_service "cyberrange-logstash" && ((passed++)) || true
    ((total++)); check_docker_service "cyberrange-grafana" && ((passed++)) || true
    ((total++)); check_docker_service "cyberrange-redis" && ((passed++)) || true
    ((total++)); check_docker_service "cyberrange-filebeat" && ((passed++)) || true
    echo ""
    
    echo -e "${YELLOW}Checking Service Connectivity:${NC}"
    ((total++)); check_service "Logstash Beats" "172.16.200.137" "5044" && ((passed++)) || true
    ((total++)); check_service "Logstash HTTP" "172.16.200.137" "9600" && ((passed++)) || true
    ((total++)); check_service "Grafana" "172.16.200.138" "3000" && ((passed++)) || true
    ((total++)); check_service "Redis" "172.16.200.140" "6379" && ((passed++)) || true
    ((total++)); check_service "Elasticsearch" "172.16.200.136" "9200" && ((passed++)) || true
    echo ""
    
    echo -e "${YELLOW}Checking File System:${NC}"
    local dirs=("/opt/cyberrange" "/opt/cyberrange/pcap-data" "/var/log/cyberrange")
    for dir in "${dirs[@]}"; do
        ((total++))
        if [ -d "$dir" ]; then
            echo -e "${GREEN}✓${NC} Directory '$dir' exists"
            ((passed++))
        else
            echo -e "${RED}✗${NC} Directory '$dir' not found"
        fi
    done
    echo ""
    
    echo -e "${YELLOW}Testing Elasticsearch Integration:${NC}"
    ((total++))
    if curl -s "http://172.16.200.136:9200/_cluster/health" | jq -r '.status' | grep -q -E "(yellow|green)"; then
        echo -e "${GREEN}✓${NC} Elasticsearch cluster is healthy"
        ((passed++))
    else
        echo -e "${RED}✗${NC} Elasticsearch cluster is not healthy"
    fi
    
    ((total++))
    if curl -s "http://172.16.200.136:9200/_cat/indices" | grep -q "cyberrange"; then
        echo -e "${GREEN}✓${NC} CyberRange indices exist in Elasticsearch"
        ((passed++))
    else
        echo -e "${YELLOW}⚠${NC} No CyberRange indices found (normal on fresh deployment)"
        ((passed++))
    fi
    echo ""
    
    echo -e "${YELLOW}Testing Packet Capture:${NC}"
    ((total++))
    if ls /opt/cyberrange/pcap-data/*.pcap >/dev/null 2>&1; then
        local pcap_count=$(ls -1 /opt/cyberrange/pcap-data/*.pcap | wc -l)
        echo -e "${GREEN}✓${NC} Found $pcap_count packet capture file(s)"
        ((passed++))
    else
        echo -e "${YELLOW}⚠${NC} No packet capture files found (normal if no traffic yet)"
        ((passed++))
    fi
    echo ""
    
    # Summary
    echo -e "${BLUE}Verification Summary:${NC}"
    echo -e "Passed: ${GREEN}$passed${NC}/$total tests"
    
    if [ $passed -eq $total ]; then
        echo -e "${GREEN}✓ Phase 1 infrastructure is fully operational!${NC}"
        echo ""
        echo -e "${YELLOW}Access URLs:${NC}"
        echo "• Grafana: http://172.16.200.138:3000 (admin/cyberrange2024)"
        echo "• Logstash: http://172.16.200.137:9600"
        echo "• Elasticsearch: http://172.16.200.136:9200"
        echo ""
        echo -e "${YELLOW}Ready to proceed to Phase 2: Scoring & Game Engine${NC}"
        return 0
    elif [ $passed -gt $((total * 3 / 4)) ]; then
        echo -e "${YELLOW}⚠ Phase 1 infrastructure is mostly operational${NC}"
        echo -e "${YELLOW}Some non-critical services may need attention${NC}"
        return 1
    else
        echo -e "${RED}✗ Phase 1 infrastructure has significant issues${NC}"
        echo -e "${RED}Please check deployment logs and retry${NC}"
        return 2
    fi
}

# Run verification
main "$@"

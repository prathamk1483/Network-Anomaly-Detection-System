#!/bin/bash

# Define log file with timestamp in the current directory
LOG_FILE="network_logs_$(date +"%Y%m%d_%H%M%S").log"

# Collect network logs
{
    echo "===== Network Logs Collected on $(date) ====="

    # Active network connections with process names
    echo -e "\n--- Active Network Connections (with Process Names) ---"
    netstat -ano | while read -r line; do
        pid=$(echo "$line" | awk '{print $5}')
        process=$(wmic process where "ProcessId=$pid" get Name 2>/dev/null | tail -n 2)
        echo "$line - $process"
    done

    # Network interfaces and their configurations
    echo -e "\n--- Network Interfaces and IP Addresses ---"
    ipconfig /all  # Windows alternative to 'ip addr show'

    # Routing table
    echo -e "\n--- Routing Table ---"
    route print  # Windows alternative to 'ip route show'

    # Firewall rules (Windows does not use iptables/nftables)
    echo -e "\n--- Firewall Rules (Windows Firewall) ---"
    netsh advfirewall show allprofiles

    # Enable Firewall Logging
    echo -e "\n--- Enabling Firewall Logging ---"
    netsh advfirewall set allprofiles logging allowedconnections enable
    netsh advfirewall set allprofiles logging droppedconnections enable

    # Security event logs (login failures, authentication attempts)
    echo -e "\n--- Security Event Logs ---"
    wevtutil qe Security /c:10 /rd:true /f:text 2>/dev/null | grep -i "failed" || echo "No security logs found"

    # Network statistics (includes abnormal data transfer detection)
    echo -e "\n--- Network Statistics ---"
    netstat -s  # Equivalent for both Linux and Windows
    echo -e "\n--- Data Transfer Statistics ---"
    netstat -e  # Bytes sent and received

    # Capturing DNS cache
    echo -e "\n--- DNS Query Log ---"
    powershell -Command "Get-DnsClientCache | Select-Object Name, Data" 2>/dev/null || echo "Failed to retrieve DNS cache"

    # Checking DNS resolution
    echo -e "\n--- DNS Resolution Test ---"
    nslookup google.com  # 'dig' is not available by default in Windows

} > "$LOG_FILE"

# Set permissions (Only relevant on Unix-like systems, ignored in Git Bash)
chmod 600 "$LOG_FILE" 2>/dev/null || echo "chmod not applicable on Windows"

echo "Network logs collected and saved to: $(pwd)/$LOG_FILE"

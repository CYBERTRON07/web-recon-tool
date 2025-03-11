#!/bin/bash

# WebRecon - Website Reconnaissance Tool
# Author: Claude
# Date: March 8, 2025
# Description: Collects information about a target website including DNS records,
# whois data, HTTP headers, technologies used, open ports, and more.

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}This script must be run as root${NC}" 
   exit 1
fi

# Check if required tools are installed
required_tools=("whois" "host" "dig" "nmap" "curl" "whatweb" "wafw00f" "gobuster" "subfinder" "amass")
missing_tools=()

for tool in "${required_tools[@]}"; do
    if ! command -v "$tool" &> /dev/null; then
        missing_tools+=("$tool")
    fi
done

if [ ${#missing_tools[@]} -ne 0 ]; then
    echo -e "${YELLOW}The following required tools are missing:${NC}"
    for tool in "${missing_tools[@]}"; do
        echo "- $tool"
    done
    
    read -p "Do you want to install them now? (y/n): " install_choice
    if [[ $install_choice == "y" || $install_choice == "Y" ]]; then
        apt-get update
        for tool in "${missing_tools[@]}"; do
            echo -e "${BLUE}Installing $tool...${NC}"
            apt-get install -y "$tool"
        done
    else
        echo -e "${RED}Exiting: Required tools not installed.${NC}"
        exit 1
    fi
fi

# Help function
show_help() {
    echo -e "${GREEN}WebRecon - Website Reconnaissance Tool${NC}"
    echo "Usage: $0 -d <domain> [options]"
    echo ""
    echo "Options:"
    echo "  -d <domain>     Target domain to scan (required)"
    echo "  -o <directory>  Output directory (default: ./webrecon_results)"
    echo "  -p              Perform port scan"
    echo "  -s              Enumerate subdomains"
    echo "  -a              Run all scans (intensive)"
    echo "  -h              Show this help message"
    echo ""
    echo "Example: $0 -d example.com -o /path/to/output -a"
}

# Set default values
DOMAIN=""
OUTPUT_DIR="./webrecon_results"
PORT_SCAN=false
SUBDOMAIN_ENUM=false
ALL_SCANS=false

# Parse command line arguments
while getopts "d:o:psha" opt; do
    case $opt in
        d) DOMAIN="$OPTARG" ;;
        o) OUTPUT_DIR="$OPTARG" ;;
        p) PORT_SCAN=true ;;
        s) SUBDOMAIN_ENUM=true ;;
        a) ALL_SCANS=true ;;
        h) show_help; exit 0 ;;
        *) echo -e "${RED}Invalid option${NC}"; show_help; exit 1 ;;
    esac
done

# Check if domain is provided
if [ -z "$DOMAIN" ]; then
    echo -e "${RED}Error: Target domain is required${NC}"
    show_help
    exit 1
fi

# If ALL_SCANS is true, enable all options
if [ "$ALL_SCANS" = true ]; then
    PORT_SCAN=true
    SUBDOMAIN_ENUM=true
fi

# Create output directory
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
OUTPUT_DIR="${OUTPUT_DIR}/${DOMAIN}_${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"
echo -e "${GREEN}Results will be saved to: ${OUTPUT_DIR}${NC}"

# Function to log output to both console and file
log() {
    local msg="$1"
    local file="$2"
    echo -e "$msg" | tee -a "${OUTPUT_DIR}/${file}.txt"
}

# Basic information gathering
gather_basic_info() {
    echo -e "\n${CYAN}[+] Gathering basic information for ${DOMAIN}${NC}\n"
    
    # WHOIS Information
    echo -e "${PURPLE}[*] WHOIS Information${NC}"
    whois "$DOMAIN" > "${OUTPUT_DIR}/whois.txt"
    echo -e "${GREEN}WHOIS data saved to ${OUTPUT_DIR}/whois.txt${NC}"
    
    # DNS Information
    echo -e "\n${PURPLE}[*] DNS Records${NC}"
    log "$(host -a "$DOMAIN")" "dns_records"
    
    # Get IP address
    IP=$(dig +short "$DOMAIN" | head -n 1)
    if [ -n "$IP" ]; then
        echo -e "\n${PURPLE}[*] IP Information: $IP${NC}"
        log "$(whois "$IP")" "ip_info"
    fi
    
    # HTTP Headers
    echo -e "\n${PURPLE}[*] HTTP Headers${NC}"
    log "$(curl -s -I -L "http://${DOMAIN}")" "http_headers"
    log "$(curl -s -I -L "https://${DOMAIN}")" "https_headers"
    
    # SSL/TLS Information
    echo -e "\n${PURPLE}[*] SSL/TLS Information${NC}"
    log "$(timeout 10s openssl s_client -connect "${DOMAIN}:443" -showcerts </dev/null 2>/dev/null | openssl x509 -text)" "ssl_info"
    
    # Technology detection using WhatWeb
    echo -e "\n${PURPLE}[*] Technology Detection${NC}"
    log "$(whatweb -a 3 "$DOMAIN")" "technologies"
    
    # WAF Detection
    echo -e "\n${PURPLE}[*] WAF Detection${NC}"
    log "$(wafw00f "https://${DOMAIN}")" "waf_detection"
}

# Directory enumeration
enumerate_directories() {
    echo -e "\n${CYAN}[+] Enumerating directories for ${DOMAIN}${NC}\n"
    
    # Create wordlist directory if it doesn't exist
    WORDLIST="/usr/share/wordlists/dirb/common.txt"
    if [ ! -f "$WORDLIST" ]; then
        echo -e "${YELLOW}Default wordlist not found. Using built-in small wordlist.${NC}"
        WORDLIST="${OUTPUT_DIR}/wordlist.txt"
        echo -e "admin\nlogin\nwp-admin\nwp-content\nwp-includes\napi\nassets\njs\ncss\nimages\nuploads\nbackup\nconfig\ndb\ndev\ntest\nprod\nstorage\nblog\nforum\nshop\ncart\ncheckout\nsecure\naccount\nuser\nadmin\npanel\ndashboard\nrobot.txt\nsitemap.xml" > "$WORDLIST"
    fi
    
    echo -e "${PURPLE}[*] Directory Enumeration${NC}"
    gobuster dir -u "https://${DOMAIN}" -w "$WORDLIST" -q -o "${OUTPUT_DIR}/directories.txt"
    echo -e "${GREEN}Directory enumeration results saved to ${OUTPUT_DIR}/directories.txt${NC}"
}

# Port scanning
perform_port_scan() {
    if [ "$PORT_SCAN" = true ]; then
        echo -e "\n${CYAN}[+] Performing port scan on ${DOMAIN}${NC}\n"
        
        # Resolve domain to IP if needed
        if [[ ! "$DOMAIN" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            IP=$(dig +short "$DOMAIN" | head -n 1)
            if [ -z "$IP" ]; then
                echo -e "${RED}Could not resolve domain to IP address${NC}"
                return
            fi
            echo -e "${PURPLE}[*] Resolved $DOMAIN to $IP${NC}"
        else
            IP="$DOMAIN"
        fi
        
        echo -e "${PURPLE}[*] Quick Port Scan (top 1000 ports)${NC}"
        nmap -sV --version-intensity 2 -T4 "$IP" -oN "${OUTPUT_DIR}/port_scan.txt"
        echo -e "${GREEN}Port scan results saved to ${OUTPUT_DIR}/port_scan.txt${NC}"
    fi
}

# Subdomain enumeration
enumerate_subdomains() {
    if [ "$SUBDOMAIN_ENUM" = true ]; then
        echo -e "\n${CYAN}[+] Enumerating subdomains for ${DOMAIN}${NC}\n"
        
        # Using Subfinder
        echo -e "${PURPLE}[*] Running Subfinder${NC}"
        subfinder -d "$DOMAIN" -o "${OUTPUT_DIR}/subfinder_results.txt" -silent
        
        # Using Amass (passive mode for speed)
        echo -e "${PURPLE}[*] Running Amass (passive mode)${NC}"
        amass enum -passive -d "$DOMAIN" -o "${OUTPUT_DIR}/amass_results.txt"
        
        # Combine and sort unique results
        cat "${OUTPUT_DIR}/subfinder_results.txt" "${OUTPUT_DIR}/amass_results.txt" | sort -u > "${OUTPUT_DIR}/subdomains.txt"
        echo -e "${GREEN}Found $(wc -l < "${OUTPUT_DIR}/subdomains.txt") unique subdomains. Saved to ${OUTPUT_DIR}/subdomains.txt${NC}"
        
        # Probe discovered subdomains
        echo -e "${PURPLE}[*] Probing discovered subdomains${NC}"
        if command -v httprobe &> /dev/null; then
            cat "${OUTPUT_DIR}/subdomains.txt" | httprobe > "${OUTPUT_DIR}/live_subdomains.txt"
            echo -e "${GREEN}Live subdomains saved to ${OUTPUT_DIR}/live_subdomains.txt${NC}"
        else
            echo -e "${YELLOW}httprobe not installed. Skipping subdomain probing.${NC}"
        fi
    fi
}

# Screenshot functionality
take_screenshots() {
    if command -v gowitness &> /dev/null; then
        echo -e "\n${CYAN}[+] Taking screenshots${NC}\n"
        
        # Take screenshot of main domain
        gowitness single "https://${DOMAIN}" --destination "${OUTPUT_DIR}/screenshots/"
        
        # Take screenshots of subdomains if enumerated
        if [ "$SUBDOMAIN_ENUM" = true ] && [ -f "${OUTPUT_DIR}/live_subdomains.txt" ]; then
            gowitness file -f "${OUTPUT_DIR}/live_subdomains.txt" --destination "${OUTPUT_DIR}/screenshots/"
        fi
        
        echo -e "${GREEN}Screenshots saved to ${OUTPUT_DIR}/screenshots/${NC}"
    else
        echo -e "${YELLOW}gowitness not installed. Skipping screenshots.${NC}"
    fi
}

# Generate report
generate_report() {
    echo -e "\n${CYAN}[+] Generating report${NC}\n"
    
    REPORT="${OUTPUT_DIR}/report.md"
    
    # Create report header
    cat > "$REPORT" << EOF
# Web Reconnaissance Report for $DOMAIN
**Date:** $(date)

## Summary
This report contains reconnaissance information gathered for $DOMAIN.

## Basic Information
EOF
    
    # Add IP information
    IP=$(dig +short "$DOMAIN" | head -n 1)
    echo "- **Domain:** $DOMAIN" >> "$REPORT"
    echo "- **IP Address:** $IP" >> "$REPORT"
    
    # Add WHOIS summary
    echo -e "\n## WHOIS Summary" >> "$REPORT"
    if [ -f "${OUTPUT_DIR}/whois.txt" ]; then
        REGISTRAR=$(grep "Registrar:" "${OUTPUT_DIR}/whois.txt" | head -n 1 | cut -d ":" -f 2- | sed 's/^[ \t]*//')
        CREATION=$(grep -E "Creation Date:|created:" "${OUTPUT_DIR}/whois.txt" | head -n 1 | cut -d ":" -f 2- | sed 's/^[ \t]*//')
        echo "- **Registrar:** $REGISTRAR" >> "$REPORT"
        echo "- **Creation Date:** $CREATION" >> "$REPORT"
        echo "- **[Full WHOIS Information](whois.txt)**" >> "$REPORT"
    fi
    
    # Add DNS information
    echo -e "\n## DNS Records" >> "$REPORT"
    echo "- **[Full DNS Records](dns_records.txt)**" >> "$REPORT"
    
    # Add discovered technologies
    echo -e "\n## Technologies Detected" >> "$REPORT"
    if [ -f "${OUTPUT_DIR}/technologies.txt" ]; then
        grep -o "\[.*\]" "${OUTPUT_DIR}/technologies.txt" | sort -u | sed 's/\[/- /g' | sed 's/\]//g' >> "$REPORT"
        echo -e "\n- **[Full Technology Details](technologies.txt)**" >> "$REPORT"
    fi
    
    # Add port scan information
    if [ "$PORT_SCAN" = true ]; then
        echo -e "\n## Open Ports and Services" >> "$REPORT"
        if [ -f "${OUTPUT_DIR}/port_scan.txt" ]; then
            echo "- **[Port Scan Results](port_scan.txt)**" >> "$REPORT"
            grep "open" "${OUTPUT_DIR}/port_scan.txt" | grep -v "filtered" | sed 's/^/- /g' >> "$REPORT"
        fi
    fi
    
    # Add subdomain information
    if [ "$SUBDOMAIN_ENUM" = true ]; then
        echo -e "\n## Discovered Subdomains" >> "$REPORT"
        if [ -f "${OUTPUT_DIR}/subdomains.txt" ]; then
            echo "Total subdomains discovered: $(wc -l < "${OUTPUT_DIR}/subdomains.txt")" >> "$REPORT"
            echo "- **[Full Subdomain List](subdomains.txt)**" >> "$REPORT"
            
            if [ -f "${OUTPUT_DIR}/live_subdomains.txt" ]; then
                echo "- **[Live Subdomains](live_subdomains.txt)**" >> "$REPORT"
            fi
        fi
    fi
    
    # Add directory enumeration results
    echo -e "\n## Directory Enumeration" >> "$REPORT"
    if [ -f "${OUTPUT_DIR}/directories.txt" ]; then
        echo "- **[Directory Enumeration Results](directories.txt)**" >> "$REPORT"
    fi
    
    # Add WAF information
    echo -e "\n## Web Application Firewall" >> "$REPORT"
    if [ -f "${OUTPUT_DIR}/waf_detection.txt" ]; then
        WAF=$(grep "identified" "${OUTPUT_DIR}/waf_detection.txt" | tail -n 1)
        if [[ "$WAF" == *"No WAF"* ]]; then
            echo "- No WAF detected" >> "$REPORT"
        else
            echo "- $WAF" >> "$REPORT"
        fi
    fi
    
    echo -e "${GREEN}Report generated: ${OUTPUT_DIR}/report.md${NC}"
}

# Main execution flow
echo -e "${GREEN}Starting reconnaissance on ${DOMAIN}...${NC}"
start_time=$(date +%s)

gather_basic_info
enumerate_directories
perform_port_scan
enumerate_subdomains
take_screenshots
generate_report

end_time=$(date +%s)
runtime=$((end_time - start_time))
minutes=$((runtime / 60))
seconds=$((runtime % 60))

echo -e "\n${GREEN}Reconnaissance completed in ${minutes}m ${seconds}s${NC}"
echo -e "${BLUE}Results saved to: ${OUTPUT_DIR}${NC}"
echo -e "${YELLOW}Report available at: ${OUTPUT_DIR}/report.md${NC}"

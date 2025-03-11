# WebRecon - Website Reconnaissance Tool

## Overview
**WebRecon** is a powerful and automated website reconnaissance tool that assists security researchers, penetration testers, and cyber defenders by gathering critical information about a target domain. It collects WHOIS data, DNS records, HTTP headers, open ports, subdomains, technologies used, and more. The tool automates multiple reconnaissance tasks, saving valuable time and effort during the information-gathering phase of security assessments.

## Features
- **WHOIS Information**: Fetch domain registration details.
- **DNS Records**: Retrieve detailed DNS records for the target domain.
- **HTTP Headers**: Capture HTTP and HTTPS headers for the target.
- **SSL/TLS Information**: Get SSL certificate details.
- **Technology Detection**: Identify technologies used on the website.
- **WAF Detection**: Detect the presence of Web Application Firewalls (WAF).
- **Port Scanning**: Perform a port scan to find open ports and services.
- **Subdomain Enumeration**: Discover subdomains associated with the domain.
- **Directory Enumeration**: Discover hidden directories on the server.
- **Screenshots**: Take screenshots of the website and subdomains.
- **Report Generation**: Generate a comprehensive markdown report.

## Requirements

Before running WebRecon, ensure you have the following tools installed:
- `whois`
- `host`
- `dig`
- `nmap`
- `curl`
- `whatweb`
- `wafw00f`
- `gobuster`
- `subfinder`
- `amass`
- `httprobe` (optional, for live subdomain probing)
- `gowitness` (optional, for screenshots)

### Missing Tools
If any required tools are missing, the script will prompt you to install them automatically.

## Installation

1. Clone the repository:

```bash
git clone https://github.com/yourusername/WebRecon.git
cd WebRecon

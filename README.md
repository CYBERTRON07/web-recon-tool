Installation and Usage
Installation
Clone the repository or download the script
git clone https://github.com/yourusername/WebRecon.git
cd WebRecon
chmod +x webrecon.sh
./webrecon.sh -d example.com -o /path/to/output -a
-d <domain>: Target domain to scan (required).
-o <directory>: Output directory (default is ./webrecon_results).
-p: Perform port scan.
-s: Enumerate subdomains.
-a: Run all scans (intensive).
-h: Show help message
Example Usage
Basic Scan
./webrecon.sh -d example.com
Port Scan and Subdomain Enumeration:
./webrecon.sh -d example.com -p -s

from colorama import Fore, init, Style
import pyfiglet
import os
import requests
#program
os.system("clear")
def Instalasi():
    print(Fore.RED,"Update System",Style.RESET_ALL)
    os.system("apt update -y")
    print(Fore.RED,"Install libraries",Style.RESET_ALL)
    os.system("pip install colorama")
    os.system("pip install requests")
    os.system("pip install pyfiglet")
#welcome mesassage
def get_public_ip():
    try:
        ip = requests.get("https://api.ipify.org").text
        return ip
    except:
        return "Tidak dapat mengambil IP publik."
ip = get_public_ip()

def WM():
    os.system("clear")
    init(autoreset=True)
    banner = pyfiglet.figlet_format("WeakDetect")
    print(Fore.MAGENTA + banner)

def WM2():
    print("╔═════════════════════════════════════════╗")
    print("║Author    :\t Xvenn-03                 ║")
    print("║Github    :\t github.com/Xvenn-03      ║")
    print(f"║ip public :\t {ip}            ║")
    print("║mesassage :\t "+Fore.YELLOW+"[!]"+Style.RESET_ALL+"                      ║")
    print("╚═════════════════════════════════════════╝")

def menu():
    print("[1] Open Menu")
    print("[2] Exit program")
    while True:
        pilihan_device = input("\nInput option > ")
        if pilihan_device == "1":
            print("\nEnter downloading menu\n")
            print("[1] "+Fore.RED+"Nmap")
            print("- Network scaning, Port detection, Service identification")
            print("\n[2] "+Fore.RED+"Sqlmap")
            print("- Detection & Xploit Sql injection")
            print("\n[3] "+Fore.RED+"John The Ripper")
            print("- Cracking Password")
            print("\n[4] "+Fore.RED+"Metasploit Framework")
            print("- Vulnerabilities testing, Xploit, Network penetration")
            print("\n[5] "+Fore.RED+"Aircrack-Ng")
            print("- Wifi security")
            print("\n[6] "+Fore.RED+"Hydra")
            print("- Brute-force SSH, FTP, HTTPA")
            print("\n[7] "+Fore.RED+"Wireshark")
            print("- Network packet analysis for traffic inspection")
            print("\n[8] "+Fore.RED+"Brute suite")
            print("- web application security testing ")
            print("\n[9] "+Fore.RED+"Nikto")
            print("- Scanner vuln")
            print("\n[10] "+Fore.RED+"Dirb/Dirbuster")
            print("- Find hidden directories or files on web servers")
            print("\n[11] "+Fore.RED+"XSStrike")
            print("- Xss vulnerability testing tool on web applications")
            print("\n[12] "+Fore.RED+"WPSeku")
            print("- Special tool to check vulnerabilities in WordPress")
            print("\n[13] "+Fore.RED+"Recon-Ng")
            print("- Open source information collector framework")
            print("\n[14] "+Fore.RED+"Dirsearch")
            print("- Brute force search of directories and files on a web server")
            print("\n[15 "+Fore.RED+"Wfuzz]")
            print("- Find hidden endpoint")
            print("\n[16] "+Fore.RED+"Sublist3r")
            print("- Collect subdomains automatically")
            print("\n[17] "+Fore.RED+"Whois")
            print("- Get information about domain")
            print("\n[18] "+Fore.RED+"Cloudflare Bypass")
            print("- Bypass cloudflare in search of original server ip")
            pilihan_tool = int(input("\nEnter option > "))
            #cloudflare bypass
            if pilihan_tool == 18:
                print("\nCloudflare Bypass menuu")
                print("[1] Installation")
                print("[2] how to use?")
                pilihan_18 = int(input("Input option > "))
                if pilihan_18 == 1:
                    os.system("git clone https://github.com/Annihilaterz/cf-bypass.git")
                    break
                elif pilihan_18 == 2:
                    print('''
💡 What is cf-bypass?
`cf-bypass` is a tool to bypass Cloudflare protection (DDoS mitigation, WAF, and CAPTCHA) when testing or scraping websites.  

🛠 Basic Requirements 
Before using `cf-bypass`:  
1. Install Python 3.  
2. Clone the tool from GitHub:  
git clone https://github.com/Annihilaterz/cf-bypass.git
3. Navigate to the folder:  
cd cf-bypass
4. Install required dependencies:  
pip install -r requirements.txt

📌 Basic Usage 
1. Check if a website is protected by Cloudflare  
Run:  
python cf-bypass.py -u "https://example.com"
- `-u` = Target URL.  

2. Bypass Cloudflare and fetch page content 
python cf-bypass.py -u "https://example.com" --get
- `--get` = Fetches the page content after bypassing Cloudflare.  

3. Save the result to a file
python cf-bypass.py -u "https://example.com" --get -o output.html
- `-o` = Saves the output to a file (e.g., `output.html`).  

4. Use a custom user-agent (optional) 
python cf-bypass.py -u "https://example.com" --get --user-agent "Mozilla/5.0"
- `--user-agent` = Changes the browser identity to avoid detection.  

⚠️ Warning:
- Use this tool only on websites you own or have permission to test.  
- Unauthorized bypassing of Cloudflare protections may be illegal.  

This guide covers the basics. For advanced options, check the tool’s `README.md` or run:  
python cf-bypass.py --help
''')
                    break
                    #Whois
            elif pilihan_tool == 17:
                print("\nWhois menu")
                print("[1] Installation")
                print("[2] how to use?")
                pilihan_17 = int(input("Input option > "))
                if pilihan_17 == 1:
                    os.system("apt install whois")
                    break
                elif pilihan_17 == 2:
                    print('''
💡 What is WHOIS?  
WHOIS is a tool to look up domain or IP address information, like who owns a website, when it was registered, and its expiration date.  

🛠 Basic Requirements  
Before using WHOIS:  
- Install WHOIS (if not pre-installed).  
  - Linux/macOS: Usually built-in (run `whois` in terminal).  
  - Windows: Download from [Sysinternals](https://learn.microsoft.com/en-us/sysinternals/) or use online WHOIS tools.  
- Know a domain name (e.g., `example.com`) or IP address.  

📌 Basic Commands  

1. Look up domain information  
whois example.com
- Shows the domain’s registrar, owner, creation/expiry dates, and contact info.  

2. Look up IP address information  
whois 8.8.8.8
- Displays the IP’s owner (e.g., Google’s DNS server).  

3. Check domain availability  
whois newdomain123.com
- If the domain is **not registered**, you’ll see "No match for domain".  

4. Limit output (for faster results)  
whois -H example.com
- `-H` = Hide legal disclaimers (shorter output).  

⚠️ Warning:  
- WHOIS data may be private (due to GDPR/registrar privacy).  
- Use WHOIS ethically—don’t spam domain owners.  

Example Output:  
$ whois google.com

Domain Name: GOOGLE.COM  
Registry Domain ID: 2138514_DOMAIN_COM-VRSN  
Registrar: MarkMonitor Inc.  
Creation Date: 1997-09-15  
Expiration Date: 2028-09-14  
Registrant Email: abusecomplaints@markmonitor.com  
Name Server: ns1.google.com  
''')
                    break
                    #Sublist3r
            elif pilihan_tool == 16:
                print("\nSublist3r menu")
                print("[1] Installation")
                print("[2] How to use?")
                pilihan_16 = int(input("Input option > "))
                if pilihan_16 == 1:
                    os.system("pip install sublist3r")
                    break
                elif pilihan_16 == 2:
                    print('''
💡 What is Sublist3r?
Sublist3r is a tool to find subdomains of a website, which helps in security testing and reconnaissance.  

🛠 Basic Requirements
Before using Sublist3r:  
- Install Python (2.7 or 3.x).  
- Install Sublist3r (`pip install sublist3r`).  
- Know the target domain (e.g., `example.com`).  

📌 Basic Commands  

1. Find subdomains of a website  
sublist3r -d example.com
`-d` = the target domain.  

2. Save results to a file 
sublist3r -d example.com -o subdomains.txt
`-o` = save output to a file.  

3. Use specific search engines (like Google, Bing) 
sublist3r -d example.com -e google,bing
`-e` = specify search engines.  

4. Enable brute-force mode (for more subdomains)
sublist3r -d example.com -b
`-b` = brute-force subdomains using a wordlist.  

5. Use a custom port scan
 sublist3r -d example.com -p 80,443,8080
`-p` = scan subdomains on specific ports.  

⚠️ Warning:
- Use Sublist3r only on websites you own or have permission to test.  
- Unauthorized scanning may be illegal.  
''')
                    break
                    #Wfuzz
            elif pilihan_tool == 15:
                print("\nWfuzz menu")
                print("[1] Installation")
                print("[2] How to use?")
                pilihan_15 = int(input("Input option > "))
                if pilihan_15 == 1:
                    os.system("git clone https://github.com/xmendez/wfuzz.git")
                    break
                elif pilihan_15 == 2:
                    print('''
📥 Alternative Installation Methods  
1. Install with Python PIP  
If you have Python installed:  
pip install wfuzz
Note: Use `pip3` if `pip` points to Python 2.x.  

2. Clone from GitHub (Manual Build)  
git clone https://github.com/xmendez/wfuzz.git
cd wfuzz
python setup.py install  # or "python3 setup.py install"
                          ```  
3. Using Docker 
Pull the official image:  
docker pull xmendez/wfuzz
Run WFuzz in a container:  
docker run -it xmendez/wfuzz wfuzz --help

4. **Download Precompiled Binaries 
Check the [Releases Page](https://github.com/xmendez/wfuzz/releases) for standalone binaries.  

🔧 Post-Install Check  
Verify WFuzz works:  
wfuzz --version

📌 Notes  
- Dependencies: WFuzz requires Python 3.6+.  
- Wordlists: If missing, download common wordlists (e.g., `dirb`, `rockyou.txt`) to `/usr/share/wordlists/`.  
- Errors? Install missing dependencies (e.g., `python3-dev`).  

⚡ Quick Example
Test a URL for directories:  
wfuzz -c -z file,wordlist.txt --hc 404 http://example.com/FUZZ
Let me know if you need help troubleshooting! 🛠️
                          ''')
                          #Dirsearch
                    break
            elif pilihan_tool == 14:
                print("\nDirsearch menu")
                print("[1] Installation")
                print("[2] How to use?")
                pilihan_14 = int(input("Input option > "))
                if pilihan_14 ==  1:
                    os.system("git clone https://github.com/maurosoria/dirsearch.git")
                    break
                elif pilihan_14 == 2:
                    print('''
💡 What is Dirsearch?
Dirsearch is a powerful tool to scan websites for hidden directories and files (like admin panels, backups, or sensitive files).  

🛠 Basic Requirements*
Before using Dirsearch:  
1. Install Python (required to run Dirsearch).  
2. Download Dirsearch from GitHub:  
git clone https://github.com/maurosoria/dirsearch.git
3. Navigate to the Dirsearch folder:  
cd dirsearch

📌 Basic Commands 

1. Scan a website for hidden directories/files  
python3 dirsearch.py -u http://example.com 
`-u` = target URL.  

2. Use a custom wordlist (list of paths to check) 
python3 dirsearch.py -u http://example.com -w /path/to/wordlist.txt
`-w` = specify a wordlist (default is built-in).  

3. Scan with extensions (e.g., PHP, HTML) 
python3 dirsearch.py -u http://example.com -e php,html
`-e` = file extensions to check.  

4. Limit threads (to avoid overloading the server)  
python3 dirsearch.py -u http://example.com -t 20
`-t` = number of threads (default: 25).  

5. Save results to a file 
python3 dirsearch.py -u http://example.com -o report.txt
`-o` = output file.  

⚠️ Warning:
- Use Dirsearch only on websites you own or have permission to test.  
- Unauthorized scanning is illegal and unethical.
''')
                    break
                    #Recon-Ng
            elif pilihan_tool == 13:
                print("Recon-Ng menu")
                print("[1] Installation")
                print("[2] How to use?")
                pilihan_4 = int(input("Input option > "))
                if pilihan_4 == 1:
                    print("choose device")
                    print("[1] Android (Termux)")
                    print("[2] Linux")
                    os = int(input("Input option > "))
                    if os == 1:
                        os.system("git clone https://github.com/lanmaster53/recon-ng.git")
                        break
                    elif os == 2:
                        os.system("git clone https://github.com/lanmaster53/recon-ng.git")
                        break
                elif pilihan_4 == 2:
                    print('''
💡 What is Recon-ng? 
Recon-ng is a full-featured reconnaissance tool for gathering information about targets (websites, domains, or networks). It automates OSINT (Open-Source Intelligence) tasks like domain lookup, subdomain discovery, and data leaks.

🛠 Basic Requirements  
Before using Recon-ng:  
1. Install Python (Linux/Termux).  
2. Install Recon-ng.  
3. Have a target domain (e.g., `example.com`).  

📌 Installation
Linux (Kali/Ubuntu)
```bash
# Install dependencies
sudo apt update && sudo apt install -y python3 git

# Clone Recon-ng
git clone https://github.com/lanmaster53/recon-ng.git

# Navigate to the folder
cd recon-ng

# Install requirements
pip3 install -r REQUIREMENTS

# Run Recon-ng
python3 recon-ng.py

Termux (Android) 
```bash
# Update & install Python
pkg update && pkg install -y python git

# Clone Recon-ng
git clone https://github.com/lanmaster53/recon-ng.git

# Navigate to the folder
cd recon-ng

# Install requirements
pip install -r REQUIREMENTS

# Run Recon-ng
python recon-ng.py

📌 Basic Usage
1. Start Recon-ng & Load a Workspace
# Start the tool
python3 recon-ng.py

# Create a workspace (replace 'target1')
workspaces create target1

# List workspaces
workspaces list

2. Add a Target Domain
# Add a domain (e.g., example.com)
add domains example.com

3. Use Modules for Reconnaissance
Recon-ng has built-in modules for different tasks.  

Find Subdomains
# Load the subdomain discovery module
use recon/domains-hosts/brute_hosts

# Set options
options set SOURCE example.com

# Run the module
run

Find Emails (Harvesting)  
# Load the email harvester module
use recon/contacts-hosts/harvester

# Set options
options set SOURCE example.com

# Run
run

Scan for Vulnerable URLs 
# Load a vulnerability scanner
use reporting/vulnerabilities

# Set options (if needed)
options set SOURCE example.com

# Execute
run

4. View Results 
# Show discovered hosts
show hosts

# Show emails
show contacts

# Export data to a file
export /path/to/save/results.json

5. Exit
# Exit Recon-ng
exit

⚠️ Warning  
- Use Recon-ng **only on targets you own** or have permission to test.  
- Unauthorized reconnaissance may be **illegal**.  

🔍 Example Workflow  
1. `workspaces create test`  
2. `add domains example.com`  
3. `use recon/domains-hosts/brute_hosts`  
4. `options set SOURCE example.com`  
5. `run`  
6. `show hosts`  
This will list subdomains like `admin.example.com`, `mail.example.com`, etc.  
''')
                    break
                    #WPSeku
            elif pilihan_tool == 12:
                print("\nWPSeku menu")
                print("[1] Installation")
                print("[2] How to use?")
                pilihan_4 = int(input("Input option > "))
                if pilihan_4 == 1:
                    print("choose device")
                    print("[1] Android (Termux)")
                    print("[2] Linux")
                    os = int(input("Input option > "))
                    if os == 1:
                        os.system("git clone https://github.com/m4ll0k/WPSeku.git")  
                        break
                    elif os == 2:
                        os.system("git clone https://github.com/m4ll0k/WPSeku.git")
                        break
                elif pilihan_4 == 2:
                    print('''
💡 What is WPSeku?
WPSeku is a tool to scan WordPress websites for security vulnerabilities like weak passwords, outdated plugins, and misconfigurations.  

 🛠 Basic Requirements
Before using WPSeku:  
1. Install Python and Git.  
2. Know the target WordPress site URL.  

📥 Installation
On Linux (Kali/Ubuntu/Debian) 
1. Open a terminal and run:  
git clone https://github.com/m4ll0k/WPSeku.git
cd WPSeku
pip install -r requirements.txt

On Termux (Android)  
1. Run these commands:  
pkg install python git -y
git clone https://github.com/m4ll0k/WPSeku.git
cd WPSeku
pip install -r requirements.txt
   
📌 Basic Usage 
1. Scan a WordPress Site 
python wpseku.py --target http://example.com
- `--target` = URL of the WordPress site to scan.  

2. Scan with Aggressive Detection 
python wpseku.py --target http://example.com --aggressive
- `--aggressive` = deeper scan (checks plugins, users, and versions).  

3. Enumerate WordPress Users  
python wpseku.py --target http://example.com --enumerate u
- `--enumerate u` = lists registered usernames.  

4. Scan for Vulnerable Plugins  
python wpseku.py --target http://example.com --enumerate p
- `--enumerate p` = checks installed plugins for known vulnerabilities.  

⚠️ Warning:
- Use WPSeku only on websites you own or have permission to test.  
- Unauthorized scanning is **illegal** and can lead to legal consequences.  
''')
                    break
                    #XSStrike
            elif pilihan_tool == 11:
                print("\nXSStrike menu")
                print("[1] Installation")
                print("[2] How to use?")
                pilihan_4 = int(input("Input option > "))
                if pilihan_4 == 1:
                    print("choose device")
                    print("[1] Android (Termux)")
                    print("[2] Linux")
                    os = int(input("Input option > "))
                    if os == 1:
                        os.system("pip install xsstrike")  
                        break
                    elif os == 2:
                        os.system("git clone https://github.com/s0md3v/XSStrike.git")
                        break
                elif pilihan_4 == 2:
                    print('''
💡 What is XSStrike?
XSStrike is a powerful tool for detecting and exploiting **Cross-Site Scripting (XSS)** vulnerabilities in websites.  

🛠 Basic Requirements
Before using XSStrike:  
✔ Install **Python 3** (required).  
✔ Know a URL that may be vulnerable to XSS.  

📥 Installation Linux
1. Clone the XSStrike Repository 
Run this command to download XSStrike:  
git clone https://github.com/s0md3v/XSStrike.git

2. Navigate to the XSStrike Folder 
cd XSStrike

3. Install Dependencies
pip3 install -r requirements.txt

4. Make the Script Executable (Linux Only)
chmod +x xsstrike.py

📌 Basic Usage

1. Test a URL for XSS
xsstrike.py -u "http://example.com/search?q=test
- `-u` = Target URL to test.  

2. Crawl a Website & Test for XSS 
xsstrike.py -u "http://example.com" --crawl
- `--crawl` = Automatically scan all pages of the website.  

3. Test with a Custom Payload
xsstrike.py -u "http://example.com/search?q=test" --payload "<script>alert('XSS')</script>"
- `--payload` = Use a custom XSS payload.  

4. Save Results to a File**  
xsstrike.py -u "http://example.com" --output result.txt
- `--output` = Save findings to a file.  

⚠️ Warning:
- Use XSStrike only on websites you own or have permission to test.  
- Unauthorized testing is illegal and can lead to serious consequences.
''')
                    break
                    #Dirb/dirbuster
            elif pilihan_tool == 10:
                print("\nDirb/dirbuster menu")
                print("[1] Installation")
                print("[2] How to use?")
                pilihan_4 = int(input("Input option > "))
                if pilihan_4 == 1:
                    print("choose device")
                    print("[1] Android (Termux)")
                    print("[2] Linux")
                    os = int(input("Input option > "))
                    if os == 1:
                        os.system("pkg install golang -y")  
                        os.system("go install github.com/OJ/gobuster/v3@latest")
                        break
                    elif os == 2:
                        os.system("sudo apt update && sudo apt install dirb -y")
                elif pilihan_4 == 2:
                    print('''
💡 What is DIRB/DirBuster?  
DIRB (or DirBuster) is a web directory scanner that brute-forces directories and files on a web server. It helps find hidden paths like admin panels, backups, or sensitive files.

🛠 Basic Requirements  
Before using DIRB/DirBuster:  
1. Install DIRB (Linux) or DirBuster (Termux).  
2. Know the target website URL (e.g., `http://example.com`).  
3. Use responsibly—only scan websites you own or have permission to test.  

📥 Installation 
On Linux (Debian/Ubuntu/Kali) 
sudo apt update && sudo apt install dirb -y

On Termux
DirBuster isn’t directly available, but you can use gobuster (similar tool):  
pkg install golang -y
go install github.com/OJ/gobuster/v3@latest
mv ~/go/bin/gobuster /data/data/com.termux/files/usr/bin/

📌 Basic Commands
1. Scan a Website for Directories 
dirb http://example.com
- Scans the target with a default wordlist.  

2. Use a Custom Wordlist  
dirb http://example.com /path/to/wordlist.txt
- Replace `/path/to/wordlist.txt` with a file like `common.txt` (Kali wordlists: `/usr/share/wordlists/dirb/`).  

3. Scan with Extensions (e.g., PHP, HTML)
dirb http://example.com -X .php,.html
- `-X` checks for files with these extensions.  

4. Skip Non-Existing Pages (Faster Scan)
dirb http://example.com -N 404
- `-N 404` ignores "404 Not Found" responses.  

Example Output
URL_BASE: http://example.com/  
WORDLIST_FILES: /usr/share/wordlists/dirb/common.txt  

GENERATED WORDS: 4612  
---- Scanning URL: http://example.com/ ----
+ http://example.com/admin (CODE:200|SIZE:1234)  
+ http://example.com/login (CODE:302|SIZE:0)  
+ http://example.com/backup (CODE:403|SIZE:567)  
- `CODE:200` = Found (success).  
- `CODE:403` = Forbidden (no access).  

⚠️ Warning 
- Legal Use Only: Unauthorized scanning is illegal.  
- Rate Limiting: Add `-z 100ms` to slow down requests and avoid crashing servers.  

Alternative for Termux (Gobuster) 
gobuster dir -u http://example.com -w /path/to/wordlist.txt
- `dir`: Directory brute-force mode.  
- `-w`: Wordlist path.
''')
                    break
                    #Nikto
            elif pilihan_tool == 9:
                print("\nNikto menu")
                print("[1] Installation")
                print("[2] How to use?")
                pilihan_4 = int(input("Input option > "))
                if pilihan_4 == 1:
                    os.system("git clone https://github.com/sullo/nikto.git")
                elif pilihan_4 == 2:
                    print('''
💡 What is Nikto?
Nikto is a popular open-source web server scanner that checks for vulnerabilities, misconfigurations, and outdated software on web servers.  

🛠 Basic Requirements
Before using Nikto:  
- Install **Nikto** (Linux/Termux).  
- A target URL (e.g., `http://example.com`).  
- Basic knowledge of terminal commands.  

📥 Installation
apt install perl
git clone https://github.com/sullo/nikto.git
cd nikto/program
perl nikto.pl -h

📌 Basic Usage
1. Scan a Website
nikto -h http://example.com
- `-h` = Target URL.  

2. Scan with Specific Port 
nikto -h http://example.com -p 8080
- `-p` = Specify a port (default: 80 for HTTP, 443 for HTTPS).  

3. Save Results to a File
nikto -h http://example.com -o result.txt
- `-o` = Save output to a file.  

4. Scan Using HTTPS (SSL)
nikto -h https://example.com -ssl
- `-ssl` = Force SSL mode.  

5. Update Nikto’s Database 
nikto -update
- Always update before scanning for the latest vulnerability checks.  

⚠️ Warning: 
- Use Nikto only on websites you own** or have permission to scan.  
- Unauthorized scanning is illegal and can lead to legal consequences.  
''')
                    break
                    #brutesuite
            if pilihan_tool == 8:
                print("\nBruteSuite menu")
                print("[1] Installation")
                print("[2] How to use?")
                pilihan_4 = int(input("Input option > "))
                if pilihan_4 == 1:
                    print("choose device")
                    print("[1] Android (Termux)")
                    print("[2] Linux")
                    os = int(input("Input option > "))
                    if os == 1:
                        os.system("git clone https://github.com/saracen/brutesuite")  
                        break
                    elif os == 2:
                        os.system("sudo apt install python3 python3-pip -y")
                        os.system("sudo pip3 install brutesuite")
                        break
                elif pilihan_4 == 2:
                    print('''
💡 What is BruteSuite?
BruteSuite is a collection of tools for brute-force attacks, password cracking, and security testing. It includes tools like HTTP brute-forcing, FTP brute-forcing, and more.

🛠 Installation Guide
For Linux:
1. Install Python and pip (if not already installed)
sudo apt update
sudo apt install python3 python3-pip -y

2. Install BruteSuite
sudo pip3 install brutesuite

3. Verify installation
brutesuite --version

For Termux (CLI only):
pkg update && pkg upgrade -y
pkg install python git -y
git clone https://github.com/saracen/brutesuite
cd brutesuite
pip install -r requirements.txt

📌 Basic Usage Examples
1. HTTP Basic Auth Brute Force
brutesuite http_basic -u http://example.com/admin -w passwords.txt -U admin
- `http_basic` = module for HTTP basic authentication
- `-u` = target URL
- `-w` = wordlist/password file
- `-U` = username to test

2. Form-based Login Attack
brutesuite http_form -u http://example.com/login.php -w passwords.txt -U users.txt -d "username=USER&password=PASS&submit=Login" -f "Login failed"
- `http_form` = module for form-based logins
- `-d` = POST data (USER/PASS will be replaced)
- `-f` = failure string (to identify wrong attempts)

3. FTP Brute Force
brutesuite ftp -t ftp.example.com -w passwords.txt -U admin
- `ftp` = FTP module
- `-t` = target host

4. Wordlist Management
brutesuite wordlist -i rockyou.txt -o custom_list.txt --min 6 --max 12
- `wordlist` = module to filter wordlists
- `-i` = input file
- `-o` = output file
- `--min/--max` = password length range

⚠️ Important Notes:
1. Always get permission before testing any system
2. Use `-t` (threads) carefully to avoid overloading systems
3. For complex forms, use `-v` (verbose) to debug
4. Store results with `-r results.txt` option

🔍 Example Attack Flow:
1. Create filtered wordlist
brutesuite wordlist -i big_list.txt -o filtered.txt --min 8

2. Run HTTP form attack
brutesuite http_form -u http://test.com/login -w filtered.txt -U admin -d "user=admin&pass=PASS" -f "invalid" -t 5 -r results.txt

3. Check results
cat results.txt
''')
                    break
                    #Wireshark
            elif pilihan_tool == 7:
                print("\nWireshark menu")
                print("[1] Installation")
                print("[2] How to use?")
                pilihan_4 = int(input("Input option > "))
                if pilihan_4 == 1:
                    print("choose device")
                    print("[1] Android (Termux)")
                    print("[2] Linux")
                    os = int(input("Input option > "))
                    if os == 1:
                        os.system("pkg update && pkg install tshark")  
                        break
                    elif os == 2:
                        os.system("sudo apt update && sudo apt install wireshark")
                        break
                elif pilihan_4 == 2:
                    print(''' 
💡 What is Wireshark?  
Wireshark is a network protocol analyzer that captures and inspects network traffic in real-time.  

🛠 Installation Guide 
On Linux (Debian/Ubuntu)  
1. Install Wireshark (GUI):  
sudo apt update && sudo apt install wireshark
   
2. Allow non-root users to capture packets (optional):  
sudo usermod -aG wireshark $USER
(Log out and back in to apply changes.)

On Termux (No GUI, CLI Alternative)
Since Wireshark’s GUI doesn’t work on Termux, use `tshark` (Wireshark’s CLI version):  
1. Install TShark:
   pkg update && pkg install tshark
  
2. Grant storage permissions (for saving captures):  
   termux-setup-storage
   
📌 Basic Usage
On Linux (GUI) 
1. Launch Wireshark:  
   wireshark
  
2. Capture Traffic: 
- Select a network interface (e.g., `eth0`, `wlan0`).  
- Click Start to begin capturing packets.  

3. Filter Traffic:  
- Use filters like `http`, `tcp.port==80`, or `ip.addr==192.168.1.1`.  

On Termux (CLI with TShark)
1. List available interfaces:  
tshark -D
   
2. Capture packets (replace `wlan0` with your interface):  
tshark -i wlan0
   
3. Save captures to a file:  
tshark -i wlan0 -w capture.pcap
   
4. Filter traffic (e.g., HTTP only):  
tshark -i wlan0 -Y "http"
  
5. Read a saved capture:  
tshark -r capture.pcap
   
⚠️ Warning
- Use Wireshark/TShark only on networks you own or have permission to analyze.  
- Capturing sensitive data (e.g., passwords) may be illegal without authorization.  

---

🔹 Example (Termux) 
Capture HTTP traffic and save it:  
tshark -i wlan0 -Y "http" -w http_traffic.pcap
(Press `Ctrl+C` to stop capturing.)
''')
                    break
                    #hydraa
            elif pilihan_tool == 6:
                print("\nHydra menu")
                print("[1] Installation")
                print("[2] How to use?")
                pilihan_4 = int(input("Input option > "))
                if pilihan_4 == 1:
                    print("choose device")
                    print("[1] Android (Termux)")
                    print("[2] Linux")
                    os = int(input("Input option > "))
                    if os == 1:
                        os.system("pkg install git make openssl-tool -y")  
                        os.system("git clone https://github.com/vanhauser-thc/thc-hydra")
                        break
                    elif os == 2:
                        os.system("sudo apt update && sudo apt install hydra -y")
                        break
                elif pilihan_4 == 2:
                    print('''
💡 What is THC-Hydra?  
THC-Hydra is a powerful **login brute-forcing tool** that supports many protocols (SSH, FTP, HTTP, RDP, etc.). It’s faster than regular Hydra and works well on Termux.

🛠 Installation Guide
On Linux (Kali/Debian/Ubuntu)
1. Open a terminal and run:  
   sudo apt update && sudo apt install hydra -y
   (Kali Linux already includes Hydra by default.) 

On Termux (Android) – Install THC-Hydra
1. Update Termux and install dependencies:  
   pkg update && pkg upgrade -y
   pkg install git make openssl-tool -y
   
2. Clone & compile THC-Hydra:  
   git clone https://github.com/vanhauser-thc/thc-hydra
   cd thc-hydra
   ./configure
   make && make install
    
3. Verify installation:  
hydra -h

📌 Basic THC-Hydra Commands 
1. Attack an HTTP Login Page 
Target: `http://example.com/login.php`  
Username: `admin`  
Password List: `passwords.txt`  
hydra -l admin -P passwords.txt example.com http-post-form "/login.php:user=^USER^&pass=^PASS^:F=incorrect"
- `-l` = Single username  
- `-P` = Password list file  
- `http-post-form` = HTTP form attack  
- `F=incorrect` = Failure message (stops if seen)  

2. Brute-Force SSH 
hydra -L usernames.txt -P passwords.txt -t 4 ssh://192.168.1.1
- `-t 4` = 4 threads (prevents crashes)  
- `ssh://` = Target protocol  

3. Attack FTP Login 
hydra -l ftpuser -P passwords.txt ftp://192.168.1.1

4. Attack WordPress Admin Panel*
hydra -L users.txt -P passwords.txt example.com http-post-form "/wp-login.php:log=^USER^&pwd=^PASS^:The password is incorrect"

⚠️ Warning
- Legal Use Only! Test only systems you own or have permission to attack.  
- Use `-t` (threads) to avoid overwhelming the target (e.g., `-t 4`).  

🔥 Pro Tips  
- **Wordlists**: Use `rockyou.txt` (`pkg install wget && wget https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt`)  
- Save Results: Add `-o saved_results.txt` to save cracked passwords.

📂 Example Workflow
1. Prepare a password list:  
echo -e "password\n123456\nadmin" > passwords.txt
   
2. Run Hydra:  
hydra -l admin -P passwords.txt 192.168.1.1 ssh
 ''')
                    break
                    #aircrack-ng
            elif pilihan_tool == 5:
                print("\nAircrack-Ng menu")
                print("[1] Installation")
                print("[2] How to use?")
                pilihan_1 = int(input("Input option > "))
                if pilihan_1 == 1:
                    os.system("git clone https://github.com/aircrack-ng/aircrack-ng.git")
                    break
                elif pilihan_1 == 2:
                    print('''
💡 What is Aircrack-ng?  
Aircrack-ng is a WiFi security toolkit for:  
- Capturing WiFi packets  
- Cracking WEP/WPA/WPA2 encryption  
- Testing network vulnerabilities  

🛠 Installation (GitHub Method)  
On Linux: 
1. Install dependencies:
sudo apt update && sudo apt install build-essential libssl-dev zlib1g-dev -y

2. Clone & compile from GitHub:  
git clone https://github.com/aircrack-ng/aircrack-ng.git
cd aircrack-ng
autoreconf -i
./configure --with-experimental
make
sudo make install

3. Verify installation: 
aircrack-ng --version
   
On Termux: 
1. Install dependencies:  
pkg update && pkg install git clang openssl -y

2. Clone & compile:* 
git clone https://github.com/aircrack-ng/aircrack-ng.git
cd aircrack-ng
./autogen.sh
./configure --with-experimental --host=arm-linux-androideabi
make
make install

📌 Basic Commands  
1. Check WiFi interfaces:  
airmon-ng

2. Enable monitor mode: 
airmon-ng start wlan0  # Replace "wlan0" with your interface

3. Scan networks: 
airodump-ng wlan0mon
- `BSSID`: Router MAC address  
- `CH`: Channel  

4. Capture handshake (WPA/WPA2): 
airodump-ng -c [CHANNEL] --bssid [BSSID] -w capture wlan0mon
 
5. Crack password:  
aircrack-ng -w /path/to/wordlist.txt capture-01.cap

⚠️ Warning:  
- Use only on networks you own or have permission to test.  
- Unauthorized access is illegal.  

🔹 Pro Tips:  
- For wordlists, use `rockyou.txt` (Kali: `/usr/share/wordlists/rockyou.txt`).  
- Monitor mode requires compatible WiFi hardware. 🚀
''')
                    break
                    #metasploit framework
            elif pilihan_tool == 4:
                print("\nMetasploit Framework")
                print("[1] Installation")
                print("[2] How to use?")
                pilihan_4 = int(input("Input option > "))
                if pilihan_4 == 1:
                    print("choose device")
                    print("[1] Android (Termux)")
                    print("[2] Linux")
                    of = int(input("Input option > "))
                    if of == 1:
                        os.system("pkg install unstable-repo -y")  
                        os.system("pkg install metasploit -y")
                        break
                    elif of == 2:
                        os.system("sudo apt install metasploit-framework -y")
                        break
                elif pilihan_4 == 2:
                    print(''' 
💡 What is Metasploit Framework?  
Metasploit is a powerful penetration testing tool used to find, exploit, and validate vulnerabilities in systems.  

🛠 Installation Guide 

On Linux (Kali/Ubuntu/Debian)
1. Update your system:
sudo apt update && sudo apt upgrade -y
 
2. Install Metasploit: 
sudo apt install metasploit-framework -y

3. Launch Metasploit:
msfconsole

On Termux (Android)
1. Update packages:
pkg update && pkg upgrade -y

2. Install dependencies:
pkg install unstable-repo -y  
pkg install metasploit -y
   
3. Run Metasploit:
bash
msfconsole
   
📌 Basic Usage (Simple Commands) 

1. Search for an exploit (e.g., for EternalBlue):  
msf
search eternalblue

2. Use an exploit module:  
msf
use exploit/windows/smb/ms17_010_eternalblue

3. Set the target (RHOST):  
msf
set RHOST [Target-IP]

4. Run the exploit:  
msf
exploit

5. If successful, you’ll get a shell (Meterpreter session). Basic Meterpreter commands: 
- `sysinfo` → View system info.  
- `screenshot` → Take a screenshot.  
- `shell` → Access the target’s command line.  
- `exit` → Close the session.  

⚠️ Warning: 
- Use Metasploit only on systems you own or have permission to test.  
- Unauthorized hacking is illegal.
''')
                    break
                    #john the ripper
            elif pilihan_tool == 3:
                print("\nJohn the ripper menu")
                print("[1] Installation")
                print("[2] How to use?")
                pilihan_3 = int(input("Input option > "))
                if pilihan_3 == 1:
                    os.system("git clone https://github.com/openwall/john -b bleeding-jumbo john")
                    break
                elif pilihan_3 == 2:
                    print('''
💡 What is John the Ripper?
John the Ripper is a powerful password-cracking tool used to recover passwords through brute-force or dictionary attacks. The GitHub version includes extra features and support for more hash types.

🛠 Installation (GitHub Version)  
1. Install Dependencies** (Termux):  
pkg update && pkg upgrade -y
pkg install git make clang openssl python -y

2. Clone & Compile:  
git clone https://github.com/openwall/john -b bleeding-jumbo
cd john/src/
./configure && make -j4
(Wait 5-15 mins for compilation)

3. Verify Installation:  
../run/john --help

📌 Basic Commands

1. Crack a MD5 Hash
echo "5f4dcc3b5aa765d61d8327deb882cf99" > hash.txt  # Hash of "password"
../run/john --format=raw-md5 hash.txt
- `--format=raw-md5` = Specifies the hash type.  

2. Use a Wordlist (e.g., rockyou.txt) 
../run/john --wordlist=rockyou.txt hash.txt
- Get `rockyou.txt`:  
cp /data/data/com.termux/files/usr/share/wordlists/rockyou.txt.gz .
gunzip rockyou.txt.gz

3. Crack ZIP/RAR Passwords
../run/zip2john file.zip > zip_hash.txt
../run/john zip_hash.txt

4. Show Cracked Passwords
../run/john --show hash.txt

5. Brute-Force Attack(4-digit PIN)  
../run/john --incremental=digits --min-length=4 --max-length=4 hash.txt

 ⚠️ Warnings 
- Legal Use Only! Test only passwords you own or have permission to crack.  
- Save Progress: Use `--session=name` to resume later.  
- Termux Limitation: Slower than PC; use `--fork=2` for multi-core.  

🔍 Example: Crack WiFi Handshake
1. Convert `.cap` to `.hccap`:  
aircrack-ng -J output capture.cap

2. Crack with John:  
../run/john --format=wpapsk output.hccap

This GitHub version supports 300+ hash types(e.g., WiFi WPA2, Linux shadow). For help:  
../run/john --list=formats  # See all supported hashes

Let me know if you need adjustments! 🔐
''')
                    break
                  #nmap
            elif pilihan_tool == 2:
                print("\nSqlmap menu")
                print("[1] Installation")
                print("[2] How to use?")
                pilihan_2 = int(input("Input option > "))
                if pilihan_2 == 1:
                    os.system("pip install sqlmap")
                    os.system("sqlmap -hh")
                    break
                elif pilihan_2 == 2:
                    print('''
SQLMap?                                                                
SQLMap is a tool to test and exploit SQL injection (SQLi) on websites.

🛠  Basic Requirements
Before using SQLMap:
Install Python and SQLMap.
Know a URL that may be vulnerable to SQL injection.

📌 Basic Commands
1. Test if a site is vulnerables
sqlmap -u "http://example.com/page.php?id=1"
-u = the target URL.

2. Find available databases
sqlmap -u "http://example.com/page.php?id=1" --dbs
--dbs = shows the databases on the server.

3. Find tables inside a database
sqlmap -u "http://example.com/page.php?id=1" -D testdb --tables 
-D = choose the database. 
--tables = shows the tables inside.

4. Find columns inside a table
sqlmap -u "http://example.com/page.php?id=1" -D testdb -T users --columns
-T = choose the table.
--columns = shows the columns (like username, password).

5. Get data from a table                                                        sqlmap -u "http://example.com/page.php?id=1" -D testdb -T users -C username,password --dum      p.
-C = choose specific columns.
--dump = get (dump) the data.

⚠️  Warning:
Use SQLMap only on websites you own or have permission to test.
Unauthorized use is illegal
''')
                    break
                    #nmap
            elif pilihan_tool == 1:
                print("\nNmap menu")
                print("[1] Installation")
                print("[2] How to use?")
                pilihan_1 = int(input("Input option > "))
                if pilihan_1 == 1:
                    os.system("apt install nmap -y")
                    os.system("nmap -h")
                    break
                elif pilihan_1 == 2:
                    print('''
🔍 What is Nmap?

Nmap (Network Mapper) is a free tool to scan and check networks or computers. It helps you find which devices are online, which ports are open, and what services are running.

🛠️ Basic Nmap Commands

1. Scan a single IP
nmap 192.168.1.1
> Scan one device to see open ports.

2. Scan a range of IPs
nmap 192.168.1.1-100
> Scan many devices in the same network.

3. Scan a whole subnet
nmap 192.168.1.0/24
> Scan all 256 IPs in the network.

4. Detect operating system
nmap -O 192.168.1.1
> Try to guess the OS (Linux, Windows, etc.).

5. Service version detection
nmap -sV 192.168.1.1
> Show what service and version is running (like Apache 2.4.6).

6. Scan specific ports
nmap -p 80,443 192.168.1.1 
> Only check port 80 (HTTP) and 443 (HTTPS).

7. Fast scan
nmap -F 192.168.1.1
> Scan common ports quickly.

8. Aggressive scan 
nmap -A 192.168.1.1
> Get OS, services, scripts, and more info (noisy).

⚠️ Tips 
Use Nmap only on networks you own or have permission to scan.
Some scans can be detected and may cause alerts.
''')
                    break
        elif pilihan_device == "2":
            exit()
        elif pilihan_device == "!":
            print(Fore.YELLOW+"hello, thank you for using my script, if possible follow my github because the account will upload python scripts there and I hope if you recode it you don't change the creator's name :)"+Style.RESET_ALL)

if __name__ == "__main__":
    pilihan = input(Fore.GREEN+"Install required libraries? y/n "+Style.RESET_ALL)
    if pilihan == "y":
        Instalasi()
    WM()
    WM2()
    menu()

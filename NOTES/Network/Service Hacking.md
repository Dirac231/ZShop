# Service Hacking
*   Host Discovery
    *   `alive() [IP_FILE/CIDR]`
    *   ICMP Polling
        *   `ping()  [IP]`
        *   Windows TTL → `128`
        *   Linux TTL         → `64`
*   Port Scanning
    *   `tcp() [IP]`
    *   `udp() [IP]`
    *   IPv6 Scan → `-6 [IPv6]`
    *   Firewalls / IDS Evasion
        *   Filtered / Missing Ports / Partial Banner / TCPWrapped
        *   Packet Tracing
            *   `-vv --packet-trace` 
            *   `trace() [IP]`
        *   Manual Fingerprint
            *   `sudo nc -vn [IP] [PORT]`
            *   `sudo ncat -nv --source-port [SRC_PORT] [IP] [PORT]`
            *   `sudo tcpdump -i [NIC] host [YOUR_IP] and [TARGET]`
            *   PCAP Wireshark Analysis
        *   Source Spoofing
            *   `-D RND:5 --dns-server [NS_SERVER] -g [SRC_PORT]`
            *   `--mac-spoof [Apple/Cisco]`
        *   Handshake Confusion
            *   `[-sT / -sA / -sF / -sN / -sX / -sW / -sM ]`
        *   Fragmenting
            *   `-f -mtu 24`
            *   `--badsum` 
            *   `--data-length 25`
            *   `--data 0xdeadbeef`
            *   `--adler32`
        *   IDLE Scan
            *   `--ip-options "L [SAME_NETWORK_IP]"`
            *   `-sI [SAME_NETWORK_IP]`
        *   FTP Bouncing
            *   `-b [USER]:[PASS]@[FTP_IP]`
            *   Anonymous → Empty `USER:PASS`
*   Service Scanning
    *   `scan() [service] [IP] [PORT]`
    *   SSL Certificates
        *   `openssl s_client -connect [HOST]:[PORT] [-starttls [SERVICE]]`
        *   NMAP Output → `ssl-*`
        *   Hosts / Domains / Sensitive Exposure
    *   Exploit Research
        *   Components                 → Service Banners / Names / Versions / Found Filenames / Processes / Strings
        *   Pentesting Methods   → [Hacktricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web) / Google / Advisories & Documentation / Native Clients & Wrappers
        *   CVEs & PoCs                  → MSF Search / Sploitus / [Splotify](https://sploitify.haxx.it/#)/ [SearchVuln](https://search-vulns.com/) / GitHub CVEs / [Shodan](https://exploits.shodan.io/welcome) / Bookmarks
        *   Exploit Debugging      → Variables / Parameters / Requests Flow
        *   Alternative & Multiple Exploits → Combine Them / Get Maximum Possible Data
    *   Password Spraying
        *   Method
            *   Recursively Update Wordlists   → Obtained & Enumerated Users / Passwords / Hashes
            *   All Authentication Services       → FFUF / Hydra / Legba / NXC / Native Clients / Local & Domain Authentication
            *   NXC 
                *   Services → FTP / SSH / SMB / LDAP / RDP / WINRM / MSSQL / WMI / NFS
                *   `nxc [SERVICE] [IP] -u [USERS.txt] -p [PASSWORDS.txt] [--local-auth] --continue-on-success`                        
                *   `nxc [SERVICE] [IP] -u [USERS.txt] -p [USERS.txt] [--local-auth] --no-bruteforce --continue-on-success`
        *   Usernames
            *   All Enumerated Usernames
            *   Default  → `root` / `Guest` / `Administrator` / CIRT Seclists
            *   Bruteforcing
                *   SMTP       → Seclists `Names.txt` / [Statistically Likely](https://github.com/insidetrust/statistically-likely-usernames) / `usergen() [FULL_NAMES.txt]`
                *   Generic   → Xato-Net
        *   Passwords
            *   Re-Used              → Cracked / Found / Hash Dumping / Local Hunting
            *   Weak                    → Usernames / Blank / [Default Credentials](https://book.hacktricks.xyz/generic-methodologies-and-resources/brute-force#default-credentials) / Xato-Net
            *   Mutations           → Hashcat Rules / [Policy Filtering](https://academy.hackthebox.com/module/57/section/506) / [PassGen](https://weakpass.com/tools/passgen) / Special Chars & Guessable Numbers (Dates / IDs / Etc…)
            *   Generated          → `pswgen() [URL]` / Personal Data → `cupp -i`
            *   Charsets / Pins  → `crunch [MIN_LEN] [MAX_LEN] [CHARSET] -o [OUT.txt]`
    *   Sensitive Files
        *   Credentials / Usernames / Hostnames / Endpoints / Connection Strings / Hashes & Encoded Values
        *   Cracking            → John + `*2john` Scripts
        *   Metadata           → `file [FILE]` / `exiftool [FILE]` → Documents / Media Content / Archives
        *   PCAP                   → Wireshark Analysis
        *   Binaries              → `binwalk` / `strings` / Ghidra / Disassembling
        *   APK / JAR           → `unzip` / JADX / MANIFEST File / Code Analysis
        *   KeePass              → `kpcli --kdb [KBDX_FILE]` / [Dump Password Recovery](https://0xdf.gitlab.io/2024/02/10/htb-keeper.html#)
        *   PuTTY SSH         → `puttygen [PUTTY.KEY] -O private-openssh -o [OUT_SSH_KEY]` → SSH Key Login
        *   Word / Excel      → `olevba [FILE]`
        *   SQLITE                → `sqlite3 [FILE]` → `.tables` → `.schema [TABLE]` → `select * from [TABLE]`
        *   XSLX                    → `unzip` / OpenOffice
*   Service Types
    *   Databases
        *   MySQL / PSQL / MongoDB / TNS
        *   Data Dumping
        *   OS Read / Upload / RCE
        *   User Enumeration & Privileges
    *   File Sharing
        *   FTP / NFS / RSYNC
        *   Sensitive Exposure
        *   File Upload
        *   FTP Direct Folder Access                 → `C:\[PATH]` / `/[PATH]` / `~` / `C:\ProgramData` / `C:\Users\[USERNAME]\AppData` 
        *   FTP Direct File Access / Traversal   → `get ../../../[FILE]` / `get [PATH/FILE]`
    *   E-Mail
        *   SMTP / IMAP / POP3
            *   Open Relaying 
            *   SPF & DMARC Spoofing
            *   Mailbox Access
            *   Username Bruteforcing
        *   Phishing
            *   `swaks --server [SMTP_IP] --to victim@[DOMAIN] --from attacker@[DOMAIN] --header "Subject: test" --body "[LINK]"`
            *   Direct Links
                *   NTLM Stealing → LLMNR Via Responder
                *   RCE                     →  HTA Files
                *   XSS                      → Cookie & Response Stealing / XHR CSRF
                *   HTTP Interception
            *   Malicious Attachment
                *   `--attach [FILE]`
                *   Macro RCE        → `metash()` + VBA / VBS
                *   Follina RCE       → [RTF / DOCX Generator](https://github.com/maxgestic/Follina-Generator)
                *   LLMNR               → NTLM-Theft Office Files / Bad-PDF
    *   SNMP
        *   Process Strings  → Usernames / Credentials / Hosts / Web Content & Services / Exploit Research
        *   IPv6 Addresses  → `[SNMPWALK_ENUM] ipAddressIfIndex.ipv6 | cut -d'"' -f2 | grep 'de:ad' | sed -E 's/(.{2}):(.{2})/\1\2/g'`
        *   Vulnerable Packages
        *   Write Privilege RCE
        *   SNMPWalk Strings → TRAP / FAILED / Sensitive Data
    *   DNS
        *   NS / SOA Servers
            *   `scan() dns [DNS_IP] [PORT]`
            *   Zone Transfers / Bruteforcing / Network Exploitation
            *   Domain Discovery
        *   A / AAAA Records
            *   `dig A    [DOMAIN] @[NS]` → IPV4 Records
            *   `dig AAAA [DOMAIN] @[NS]` → IPV6 Records
        *   MX Servers
            *   `dig MX  [DOMAIN] @[NS]` → SMTP Pentesting
            *   `dig TXT [DOMAIN] @[NS]` → [SPF Checker](https://caniphish.com/free-phishing-tools/email-spoofing-test) + [Spoofer](https://emkei.cz/) / Sensitive Exposure
        *   CNAME Takeover
            *   `takeover()  [SUBDOMAINS]`
            *   [Exploitation](https://github.com/EdOverflow/can-i-take-over-xyz) 
        *   PTR Records
            *   `ptr() [CIDR/ASN]`
    *   Windows Stack
        *   SMB / RPC / NBT / LDAP / MSSQL / KB / WINRM
        *   Non-AD RPC                               → `rpcmap.py 'ncacn_ip_tcp:[IP]'` + `python3 IOXIDResolver.py -t [IP]` → Extra IPs
        *   SMB PTH & NTLM Poisoning  → Also Without AD
        *   MSSQL LLMNR                           → Also Without AD
        *   AD Enumeration / Attacks
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
        *   Port Knocking
            *   `knock [IP] [PORT1] [PORT2] {...}`
*   Service Scanning
    *   Generic Enumeration → `scan() [service] [IP] [PORT]`
    *   SSL Certificates
        *   `openssl s_client -crlf -connect [HOST]:[PORT] [-starttls [SERVICE_NAME]]`
        *   NMAP Output → `ssl-*` Scripts
        *   Hosts / Domains / Sensitive Exposure
    *   Exploit Research
        *   Nmap Scripts                → `vulners.nse` / `vulscan` / `vuln` Category
        *   Components                 → Service Banners / Versions / Application Filenames / Processes
        *   Pentesting Methods   → [Hacktricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web) / Google / Advisories & Documentation / Blind Attempt
        *   CVEs & PoCs                  → MSF Search / Sploitus / [Splotify](https://sploitify.haxx.it/#)/ [SearchVuln](https://search-vulns.com/) / GitHub CVEs / [Shodan](https://exploits.shodan.io/welcome) / Bookmarks
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
            *   Default  → `root` / `Guest` / `Administrator` / CIRT
            *   Bruteforcing
                *   SMTP       → Seclists `Names.txt` / [Statistically Likely](https://github.com/insidetrust/statistically-likely-usernames) / `usergen() [FULL_NAMES.txt]`
                *   Generic   → Xato-Net / CIRT
                *   Services   → Ident / Finger / OpenSSH < 7.7 / Solaris FTP / Kerberos / SMTP
        *   Passwords
            *   Re-Used              → Cracked / Found / Hash Dumping / Local Hunting
            *   Weak                    → Usernames / Blank & Guest / [Default Credentials](https://book.hacktricks.xyz/generic-methodologies-and-resources/brute-force#default-credentials) / `searchpass() [SERVICE/APP]`
            *   Mutations           → Best64 + [Clem9669](https://github.com/clem9669/hashcat-rule) Rules / [Policy Filtering](https://academy.hackthebox.com/module/57/section/506) / Guessable Data (Dates / IDs / Timestamps)
            *   Generated          → `pswgen() [URL]` / `cupp -i`
            *   Charsets / Pins  → `crunch [MIN_LEN] [MAX_LEN] [CHARSET] -o [OUT.txt]`
            *   Bruteforcing      → Xato-Net / Probable-V2 / Darkweb2017 / CIRT / BetterDefault
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
        *   FTP Direct Folder Access                   → `C:\[PATH]` / `/[PATH]` / `~` / `C:\ProgramData` / `C:\Users\[USERNAME]\AppData` 
        *   FTP Direct File Access / Traversal    → `get ../../../[FILE]` / `get [PATH/FILE]`
    *   E-Mail
        *   SMTP / IMAP / POP3
            *   Open Relaying 
            *   SPF & DMARC Spoofing
            *   Mailbox Access
            *   Username Bruteforcing
            *   SMTP Smuggling
                *   `python3 smtp_smuggling_scanner.py [RECEIVER_USER] --outbound-smtp-server [IP] --port [PORT] --sender-address [SENDER_USER] [--starttls --username [USER] --password "[PASS]"]`
        *   Phishing
            *   `swaks --server [IP]:[PORT] --to victim@[DOMAIN] --from attacker@[DOMAIN] --header "Subject: test"`
            *   TLS / Auth Flags → `-tls --auth-user [USER] --auth-password [PASSWORD]`
            *   Direct Links
                *   `--body "[LINK]"`
                *   NTLM Stealing → LLMNR Via Responder
                *   HTA RCE            → `metash()` + HTA
                *   XSS                      → Cookie & Response Stealing / XHR CSRF
                *   HTTP Interception
            *   Malicious Attachment
                *   `--attach [FILE]`
                *   Macro RCE        → `metash()` + VBA / VBS → Google Docs Embedding
                *   Follina RCE       → [RTF / DOCX Generator](https://github.com/maxgestic/Follina-Generator)
                *   LLMNR               → NTLM-Theft Office Files / Bad-PDF
            *   SMTP Smuggling
                *   Postfix - [CVE-2023-51764](https://nvd.nist.gov/vuln/detail/cve-2023-51764)
                *   Arbitrary Spoofing + `\n\r` Combinations
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
        *   SMB PTH / NTLM Poisoning   → Also Without AD
        *   MSSQL LLMNR                           → Also Without AD
        *   AD Enumeration / Attacks
*   Sensitive Files
    *   Credentials / Usernames / Hostnames / Endpoints / Connection Strings / Hashes & Encoded Values
    *   Cracking            → John + `*2john` Scripts
    *   Metadata           → `file [FILE]` / `exiftool [FILE]` → Documents / Media Content / Archives
    *   PCAP                   → Wireshark Analysis
    *   Binaries              → `binwalk` / `strings` / Ghidra / Disassembling
    *   APK / JAR           → `unzip` / JADX / Code Analysis / [APKLeaks](https://github.com/dwisiswant0/apkleaks)
    *   KeePass              → `kpcli --kdb [KBDX_FILE]` / [Dump Password Recovery](https://0xdf.gitlab.io/2024/02/10/htb-keeper.html#)
    *   PuTTY SSH         → `puttygen [PUTTY.KEY] -O private-openssh -o [OUT_SSH_KEY]` → SSH Key Login
    *   Word / Excel      → `olevba [FILE]`
    *   SQLITE                → `sqlite3 [FILE]` → `.tables` → `.schema [TABLE]` → `select * from [TABLE]`
    *   XSLX                    → `unzip` / OpenOffice
*   Hashed / Encoded Strings
    *   Identification                → `hashid [HASH]` / `hashcat --identify [HASH]` / [Weakpass](https://weakpass.com/tools/lookup) / [Crackstation](https://crackstation.net/) 
    *   [Hashcat Cracking](https://github.com/unstable-deadlock/brashendeavours.gitbook.io/blob/master/pentesting-cheatsheets/hashcat-hash-modes.md)      → `hashcat -m [MODE] -a 0 [ROCKYOU/WEAKPASS] -r [HASHCAT_RULE] --force [HASH.hashcat]` + [Rules Usage](https://github.com/NotSoSecure/password_cracking_rules)
    *   John Cracking              → `john --fork=15 --wordlist=[ROCKYOU/WEAKPASS] --rules=[HASHCAT_RULE] --format=[FORMAT] [HASH.john]`
    *   Incomplete Length     → Alphanumeric Bruteforce Characters
    *   Encoded Values           → [CyberChef](https://gchq.github.io/CyberChef/) + Output Suggestion / `echo -n` + `tr -d '\n'` for CLI Encodings
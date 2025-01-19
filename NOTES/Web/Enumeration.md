# Enumeration
*   Crawling
    *   `crawl() [URL]` → Burp Sitemap + Scope Filtering + Recursively
    *   Response Data
        *   Banners / Meta-Tags / Techstack Components
        *   APIs / Files & Folders / Parameters / Forms / WSS Traffic
        *   E-Mails / Hostnames / Usernames / Credentials / Comments
        *   HREF Attributes / Broken / Alive URLs
    *   JS Mining
        *   `jsmine() [SINGLE_URL]`                              → Burp Pro Extensions
        *   Credentials / Endpoints / Parameters   → [Token Regexes](https://github.com/mazen160/secrets-patterns-db) + KeyHacks
        *   JS Functions / Native Scripts                    → Console Calls / Sensitive Exposure
        *   Dependency Confusion                             → NodeJS / React / Angular / JS Frameworks
        *   Client-Side Validation                                 → Remove JS Validation (Burp Proxy)
*   Discovery
    *   Technology Stack
        *   `techscan() [URL]`
        *   [Web Checker](https://web-check.xyz/) / [URLScan](https://urlscan.io/) / RetireJS / Wappalyzer
        *   Server Information
            *   TLS Certificate                     →  `ca.key` Stealing / Heartbleed / Domains & VHosts
            *   HTTP Methods                     → `curl -kILX OPTIONS [SERVER_URL]` 
            *   HTTP Headers                      → Server / Caching / Vary / X-Powered-By → Exploit Research 
            *   HEAD / TRACE / TRACK     → Info Disclosure / Server Time
            *   Set-Cookie                             → `PHPSESSID` / `JSESSIONID` Java / Flask / ASP.NET
            *   PUT                                          → File Uploads
            *   IIS                                             → Short-Scanning / WebDAV Exploits & Uploads
        *   Exploit Research
            *   Components                                    → Servers / Banners / Plugins / Libraries / Technologies / Applications
            *   Pentesting Methods                      → [Hacktricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web) / [HTB](https://academy.hackthebox.com/module/details/113) / Google Research / Advisories & Hardening
            *   CVEs & PoCs                                     → MSF Search / Sploitus / [Splotify](https://sploitify.haxx.it/#)/ [SearchVuln](https://search-vulns.com/) / GitHub CVEs / [Shodan](https://exploits.shodan.io/welcome)
            *   Payloads                                            → [PATT](https://github.com/swisskyrepo/PayloadsAllTheThings) / [PBOX](https://github.com/payloadbox) / WSA / Hacktricks
            *   Exploit Debugging                        → Variables / Requests Flow / Alternative Exploits
            *   Alternative & Multiple Exploits   → Combine Them / Get Maximum Possible Data
    *   Directories & Files
        *   `dirfuzz() [URL/PATH]`      → Recursive / Nested / 30X & 40X Endpoints / Crawled URLs
        *   `apifuzz() [URL]`                → REST / GraphQL Enumeration / ExpressJS URLs
        *   Wordlist Selection             → `urlgen() [URL]` / GitHub Paths / Seclists Filenames & Content / [Assetnote](https://wordlists.assetnote.io/) / Techstack
        *   [Dependency Confusion](https://github.com/visma-prodsec/confused) → `pom.xml` / `installed.json` / `composer.json` / `package.json` / `requirements.txt`
        *   GIT Endpoints
            *   `git-dumper [.GIT_URL] [OUT_DIR]`
            *   `git log` / `git show [HASH]` / `git diff [HASH_1] [HASH_2]` / `git checkout [BRANCH / .]`
            *   Privesc Sections Checks → Credential Hunting (Web Applications)
        *   Backup Files
            *   Backend Files / 403 / Inferred / Sensitive Readable Files / Configuration
            *   `bckfile() [URL]/[FILE]`
            *   `ffuf -u [URL]/FUZZ -x [BACKEND_EXT].[BACKUP_EXT] -w [COMMON/DIRB/SHORT]`
    *   Virtual Hosts
        *   Domains                            → Associated with Web Applications (TLS / Other)
        *   `addhost() [IP] [HOST]`
        *   `vhost() [DOMAIN_URL]`    → Scan Domains Recursively
    *   Parameters & Headers
        *   `paramscan() [URL/BACKEND_FILE]`
        *   `headscan()  [ROOT_URL] [METHOD]`
        *   Burp Extension  → Param Miner
    *   Request Fuzzing
        *   `paramfuzz() [QUERY_STRING]` / POST Data / Path Strings & Values / Functional Inspection
        *   Parameter & Header Reflection / Parsing / Validation
        *   Stack Traces / Verbose Errors / Debug Messages
        *   Blind Exploitation (Log4J / SQL / OS / Headers)
    *   Hash Cracking
        *   Identification             → `hashid [HASH]` / `hashcat --identify [HASH]` / [Weakpass Lookup](https://weakpass.com/tools/lookup)
        *   [Hashcat Cracking](https://github.com/unstable-deadlock/brashendeavours.gitbook.io/blob/master/pentesting-cheatsheets/hashcat-hash-modes.md)   → `hashcat -m [MODE] -a 0 [ROCKYOU/WEAKPASS] -r [HASHCAT_RULE] --force [HASH.hashcat]` + [Rules Usage](https://github.com/NotSoSecure/password_cracking_rules)
        *   John Cracking           → `john --fork=15 --wordlist=[ROCKYOU/WEAKPASS] --rules=[HASHCAT_RULE] --format=[FORMAT] [HASH.john]`
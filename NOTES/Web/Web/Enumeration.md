# Enumeration
*   Crawling
    *   Tools
        *   `crawl() [URL]`
        *   Burp Sitemap  → Scope Filtering
    *   Response Content
        *   Endpoints / Parameters / Forms / WSS Traffic
        *   E-Mails / Domains / Hostnames / User Data / Techstack Information
        *   HREFs / Absolute / Relative / Broken URLs
        *   Comments / Native JS Code
    *   JS Mining
        *   `jsmine() [SINGLE_URL]`                              → Burp Pro Extensions
        *   Credentials / Endpoints / Parameters   → [Token Regexes](https://github.com/mazen160/secrets-patterns-db) + [KeyHacks Usage](https://github.com/streaak/keyhacks)
        *   JS Functions                                                 → Console Calls / Sensitive Exposure
        *   Dependency Confusion                            → NodeJS / React / Angular / Frameworks
        *   Sensitive Exposure                                      → E-Mails / Domains / Hostnames / User Data / Techstack Information
*   Discovery
    *   Technology Stack
        *   `techscan() [URL]` → RetireJS / Wappalyzer
        *   Server Information
            *   TLS Certificate                     →  `ca.key` Stealing / Heartbleed / Sensitive Exposure
            *   HTTP Methods                     → `curl -kILX OPTIONS [SERVER_URL]` 
            *   HTTP Headers                      → Server / Cache-Control / X-Powered-By / WAF / Versions / Cookies
            *   PUT                                          → File Uploads
            *   IIS                                             → Short-Scanning / WebDAV Exploits & Uploads
            *   Set-Cookie                             → `PHPSESSID` / `JSESSIONID` / Flask / ASP.NET / Laravel
        *   Exploit Research
            *   Components                         → Servers / Headers / Banners / Plugins / Libraries / Technologies / Applications
            *   Pentesting Methods           → [Hacktricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web) / [HTB](https://academy.hackthebox.com/module/details/113) / Google Research / Advisories & Hardening / Blind Attempt
            *   CVEs & PoCs                          → MSF Search / Sploitus / [Splotify](https://sploitify.haxx.it/#)/ [SearchVuln](https://search-vulns.com/) / GitHub CVEs / [Shodan](https://exploits.shodan.io/welcome)
            *   Payloads                                 → [PATT](https://github.com/swisskyrepo/PayloadsAllTheThings) / [PBOX](https://github.com/payloadbox) / WSA / Hacktricks
            *   Known Applications            → GitHub Source / Scanners + Manual Checks / Sensitive Endpoints / Admin Panels
    *   Directories & Files
        *   `dirfuzz() [URL/PATH]`      → Recursive / Nested / 30X & 40X Endpoints / Crawled URLs
        *   `apifuzz() [URL]`                → REST / GraphQL Endpoints
        *   Wordlist Selection             → `urlgen() [URL]` / GitHub Paths / Seclists Search / [Assetnote Extensions](https://wordlists.assetnote.io/) / Techstack Specific
        *   [Dependency Confusion](https://github.com/visma-prodsec/confused) → `pom.xml` / `installed.json` / `composer.json` / `package.json` / `requirements.txt`
        *   Verbose Errors                     → 404 Pages / Stack Traces
        *   GIT Endpoints
            *   `git-dumper [.GIT_URL] [OUT_DIR]`
            *   `git log` / `git show [HASH]` / `git diff [HASH_1] [HASH_2]` / `git checkout [BRANCH / .]`
            *   Privesc Sections Checks → Credential Hunting (Web Applications)
        *   Backup Files
            *   Backend Files / 403 / Inferred / Sensitive Readable Files / Configuration
            *   `bckfile() [URL]/[FILE]`
            *   `ffuf -u [URL]/FUZZ -x [BACKEND_EXT].[BACKUP_EXT] -w [COMMON/DIRB/SHORT]`
    *   Virtual Hosts
        *   Domains                            → Associated with Web Applications (TLS / URLs)
        *   `addhost() [IP] [HOST]`
        *   `vhost() [DOMAIN_URL]`    → Scan Recursively
    *   Parameters & Headers
        *   `paramscan() [URL/BACKEND_FILE]`
        *   `headscan()  [ROOT_URL] [METHOD]`
        *   Burp Extension  → Param Miner
    *   Request Fuzzing
        *   `paramfuzz() [QUERY_STRING]` / POST Data / Path Strings & Values / Functional Inspection
        *   Parameter & Header Reflection / Parsing / Validation
        *   Stack Traces / Verbose Errors / Debug Messages
        *   Blind Exploitation (Log4J / SQL / OS / Headers)
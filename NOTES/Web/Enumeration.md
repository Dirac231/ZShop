# Enumeration
*   Practice Resources
    *   [OVWAD Vulnerable Applications](https://owasp.org/www-project-vulnerable-web-applications-directory/)
    *   Portswigger Academy
    *   PentesterLab / HTB
*   Crawling
    *   Tools
        *   `crawl() [URL]`
        *   BurpSuite → Sitemap Scope Filtering + Scanner Extensions / Audit
    *   Response Content
        *   Endpoints / Parameters / Forms / WSS Traffic
        *   E-Mails / Domains / Hostnames / User Data / Techstack Information
        *   HREFs / Absolute / Relative / Broken URLs
        *   Comments / Native JS Code
    *   JS Mining
        *   `jsmine() [SINGLE_URL]`                              → Burp Pro Extensions / [GAP](https://github.com/xnl-h4ck3r/GAP-Burp-Extension) 
        *   Credentials / Endpoints / Parameters   → [Token Regexes](https://github.com/mazen160/secrets-patterns-db) + [KeyHacks Usage](https://github.com/streaak/keyhacks)
        *   JS Functions                                                 → Console Calls / Sensitive Exposure
        *   Dependency Confusion                            → NodeJS / React / Angular / Frameworks
        *   Sensitive Exposure                                      → E-Mails / Domains / Hostnames / User Data / Techstack Information
        *   Client-Side Validation                                 → Remove Using BurpSuite / Manual Source Modification
        *   [Code Deobfuscation](http://deobfuscate.io)
*   Discovery
    *   Technology Stack
        *   Enumeration
            *   `techscan() [URL]`
            *   Browser Extensions → RetireJS / Wappalyzer / WhatRuns / BuiltWith
            *   Public Websites        → [Web Checker](https://web-check.xyz/) / [URLScan](https://urlscan.io/)
        *   TLS Enumeration
            *   `a2sv` / `testssl.sh` / CA Data / Heartbleed
            *   Certificate Authentication
                *   Steal the `ca.key` File
                *   `openssl req -x509 -new -nodes -key ca.key -sha256 -days 1024 -out dirac.pem`
                *   `openssl pkcs12 -export -in dirac.pem -inkey ca.key -out dirac.p12`
                *   Import `dirac.p12` in Firefox CA Authorities
        *   Server Information
            *   HTTP Methods                     → `curl -kILX OPTIONS [SERVER_URL]` / PUT / TRACE / Custom
            *   HTTP Headers                      → Server / Cache-Control / X-Powered-By / WAF / Versions / Cookies
            *   IIS                                             → Short-Scanning / WebDAV Exploits & Uploads
            *   Set-Cookie                             → `PHPSESSID` / `JSESSIONID` / Flask / ASP.NET / Laravel
        *   Exploit Research
            *   Components                         → Servers / Headers / Banners / Plugins / Libraries / Technologies / Applications
            *   Pentesting Methods           → [Hacktricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web) / [HTB](https://academy.hackthebox.com/module/details/113) / Google Research / Advisories & Hardening / Blind Attempt
            *   CVEs & PoCs                          → MSF + BurpSuite Proxy / Sploitus / [Splotify](https://sploitify.haxx.it/#)/ [SearchVuln](https://search-vulns.com/) / GitHub CVEs / [Shodan](https://exploits.shodan.io/welcome)
            *   Payloads                                 → [PATT](https://github.com/swisskyrepo/PayloadsAllTheThings) / [PBOX](https://github.com/payloadbox) / WSA / Hacktricks
            *   Known Applications            → GitHub Source / Scanners + Manual Checks / Sensitive Endpoints / Admin Panels
    *   Directories & Files
        *   `dirfuzz() [URL/PATH]`      → Recursive / Nested / 30X & 40X Endpoints / Crawled URLs
        *   `apifuzz() [URL]`                → REST / GraphQL Endpoints / ExpressJS URLs
        *   Wordlist Selection             → GitHub Paths / Seclists Web-Content / [Assetnote](https://wordlists.assetnote.io/) / [Wordlistgen](https://github.com/ameenmaali/wordlistgen) + [WayMore](https://github.com/xnl-h4ck3r/waymore)
        *   [Dependency Confusion](https://github.com/visma-prodsec/confused) → `pom.xml` / `installed.json` / `composer.json` / `package.json` / `requirements.txt`
        *   Verbose Errors                     → 404 Pages / Stack Traces
        *   GIT Endpoints
            *   `git-dumper [.GIT_URL] [OUT_DIR]`
            *   `git log` / `git show [HASH]` / `git diff [HASH_1] [HASH_2]` / `git checkout [BRANCH / .]`
            *   Privesc Sections Checks → Credential Hunting (Web Applications)
        *   Backup Files
            *   `bckfile() [URL]/[FILE]`
            *   Backend Files / 403 Files / Inferred / Sensitive Protected Files
    *   Virtual Hosts
        *   Domains                            → Associated with Web Applications (TLS / URLs)
        *   `addhost() [IP] [HOST]`
        *   `vhost() [DOMAIN_URL]`    → Scan Recursively
    *   Parameters & Headers
        *   `paramfuzz() [QUERY_STRING]` + Copy-As-FFUF BurpSuite Extension
        *   `paramscan() [URL/BACKEND_FILE]`
        *   `headscan()  [ROOT_URL] [METHOD]`
        *   Burp Discovery  → Param Miner
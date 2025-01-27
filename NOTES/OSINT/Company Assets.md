# Company Assets
*   Domains
    *   Root Domains
        *   [Crunchbase](https://www.crunchbase.com/)
        *   [WhoisXML](https://Reverse WHOIS) / [Whoxy](https://api.whoxy.com)
        *   [OCCRP](https://aleph.occrp.org)
        *   [BGP](https://bgp.he.net/)/ [RIPE](https://apps.db.ripe.net/db-web-ui/query?searchtext=) → `ptr() [CIDR]` + ASN Mapping 
        *   BuiltWith       → [`https://builtwith.com/relationships/[ROOT_DOMAIN]`](https://builtwith.com/relationships/[ROOT_DOMAIN]) OR [Script](https://raw.githubusercontent.com/m4ll0k/Bug-Bounty-Toolz/master/getrelationship.py) → `getrelationship.py [ROOT_DOMAIN] [COOKIE]`
        *   TM Dorking   → `"© 2019 Twitch Interactive, Inc."`
    *   Subdomains
        *   `subfind()  [ROOT DOMAIN]` → Passive Sources → API Population `amass enum -list` / Subfinder Config File
        *   `subbrute() [ROOT DOMAIN]`
        *   `subperm()  [SUBDOMAINS_FILE]`
        *   `resolve()  [SUBDOMAINS_FILE]`
        *   Link Crawling
            *   Burp Sitemap Filtering
            *   `crawl() [WEB_APP_URL]` → CLI Filtering
        *   [Cloud Ranges](http://kaeferjaeger.gay/?dir=sni-ip-ranges)
            *   `cat *.txt | grep -F ".[ROOT_DOMAIN]" | awk -F'-- ' '{print $2}'| tr ' ' '\n' | tr '[' ' ‘| sed 's/ //’| sed 's/\]//’| grep -F ".[ROOT_DOMAIN]" | sort -u`
*   Network
    *   Enumeration
        *   [BGP](https://bgp.he.net/)/ [RIPE](https://apps.db.ripe.net/db-web-ui/query?searchtext=)
        *   `asn() [ORGANIZATION]`
    *   Passive Fingerprinting
        *   `shodscan()    [ASN/CIDR/IP_LIST]`
        *   `hackstat()    [SSL/ORG/NET/ASN_SHODAN_QUERY]`
        *   `shodan domain [ROOT DOMAIN]`
        *   [Queries](https://github.com/jakejarvis/awesome-shodan-queries) & [Filters](https://www.shodan.io/search/filters)
        *   [Specific Shodan Services](https://github.com/random-robbie/My-Shodan-Scripts)
        *   [Exploitative Shodan Queries](https://github.com/HernanRodriguez1/Dorks-Shodan-2023)
        *   [ZoomEye](https://www.zoomeye.hk/) / [Censys](https://search.censys.io/) Search
    *   Active Fingerprinting
        *   `alive()       [CIDR/IP_LIST]`
        *   `fingerprint() [CIDR/IP_LIST]`
*   Web 
    *   Fingerprinting
        *   `hostmap()  [ROOT DOMAIN]`
        *   `webprobe() [RESOLVED.txt]`
        *   [DockerHub Search](https://hub.docker.com/)
    *   Scanning
        *   Nuclei         → `nuclei -l [WEB_URLS.txt] -t [TEMPLATE_FOLDER]/* -t [TEMPLATE_FOLDER2]/* {...}`
        *   Extensions → [AllForOne](https://github.com/AggressiveUser/AllForOne) / [CENT](https://github.com/xm1k3/cent) / Wordfence
    *   Archive Mining
        *   `filemine() [ROOT DOMAIN]`
        *   `paramine() [ROOT DOMAIN]` + GF-Patterns / Fuzzing
        *   `urlmine()  [ROOT DOMAIN]`
        *   [Metadata Extraction](https://github.com/dafthack/PowerMeta)
    *   GitHub Data
        *   `gitscrape() [ROOT DOMAIN]`
        *   `gitfind()   [REPOSITORY]`
        *   [GitDorking](https://raw.githubusercontent.com/Karanxa/Bug-Bounty-Wordlists/main/all-gitdorks.txt)  / [GitHub Search](https://github.com/gwen001/github-search)
        *   [Data Exposure](https://www.youtube.com/watch?v=l0YsEk_59fQ)
        *   Employee Search → Gists & Repos
    *   [Google Dorking](https://github.com/cipher387/Dorks-collections-list)
        *   `gmine() [ROOT DOMAIN]`
        *   [Cheat Sheet](https://pentestbook.six2dez.com/recon/public-info-gathering#google)
*   Cloud
    *   Enumeration
        *   `cloudfind() [ROOT DOMAIN]`
        *   [Recon Cloud](https://recon.cloud)
        *   [Exposed Buckets](https://buckets.grayhatwarfare.com/)
    *   Azure Tenancy
        *   `Import-Module AADInternals`
        *   `Invoke-AADIntReconAsOutsider -DomainName [ROOT DOMAIN]`
# Company Assets
*   Domains
    *   Root Domains
        *   [Crunchbase](https://www.crunchbase.com/)
        *   [WhoisXML](https://Reverse WHOIS)
        *   [DomainGlass](https://domain.glass/)
    *   Subdomains
        *   `subfind()  [ROOT DOMAIN]`
        *   `subbrute() [ROOT DOMAIN]`
        *   `subperm()  [SUBDOMAINS]`
        *   `resolve()  [SUBDOMAINS]`
    *   WHOIS Data
        *   `whoiscan() [ROOT DOMAIN]`
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
    *   Archive Mining
        *   `filemine() [ROOT DOMAIN]`
        *   `paramine() [ROOT DOMAIN]` + GF-Patterns / Fuzzing
        *   `urlmine()  [ROOT DOMAIN]`
        *   [Metadata Extraction](https://github.com/dafthack/PowerMeta)
    *   GitHub Data
        *   `gitscrape() [ROOT DOMAIN]`
        *   `gitfind()   [REPOSITORY]`
        *   [GitDorking](https://raw.githubusercontent.com/Karanxa/Bug-Bounty-Wordlists/main/all-gitdorks.txt) 
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
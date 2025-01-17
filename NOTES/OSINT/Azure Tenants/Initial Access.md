# Initial Access
*   Tenant Enumeration
    *   `Invoke-AADIntReconAsOutsider -DomainName [ROOT DOMAIN]`
    *   Relevant Checks
        *   SPF/DMARC Spoofing
        *   SSO Enabled → Autologon Enumeration Possible
        *   Managed DNS Takeover
        *   Horizontal DNS Correlation
*   User Enumeration
    *   Scraping
        *   `harvest()    [ROOT_DOMAIN]`
        *   `spiderscan() [ROOT_DOMAIN]`
        *   User Data OSINT
    *   Validation
        *   `Get-Content [USERS.txt] | Invoke-AADIntUserEnumerationAsOutsider -Method Normal/Autologon`
        *   `python2 o365creeper.py -f [SCRAPED-E-MAILS.txt]`
        *   [TeamsEnum](https://github.com/sse-secure-systems/TeamsEnum) + Personal Account
*   User Hijacking
    *   Spraying
        *   Enumeration with [MFAde](https://github.com/ibaiC/MFade)
        *   `Invoke-MSOLSpray -UserList [VALID-EMAILS.txt] -Password [PASS] -Verbose`
    *   Phishing
        *   [Proxy Phishing](https://github.com/rootsecdev/Azure-Red-Team#phishing-with-evilginx2) 
        *   [OAuth Phishing](https://cloud.hacktricks.xyz/pentesting-cloud/azure-security/az-unauthenticated-enum-and-initial-entry/az-illicit-consent-grant)
        *   [Device Code Phishing](https://0xboku.com/2021/07/12/ArtOfDeviceCodePhish.html) (Guest Access)
*   Azure Service Exploitation
    *   PycroBurst Blobs/Domains
    *   SAS URLs Leaks
        *   `echo [BLOB_ROOT_URL] | gau`
        *   Search Dorking
    *   [Services Exploitation Reference](https://cloud.hacktricks.xyz/pentesting-cloud/azure-security/az-services)